"""Bounded review of Linux authentication logs. Read-only; no fetch, no action.

Accepted input is syslog text from ``/var/log/auth.log`` (Debian/Ubuntu),
``/var/log/secure`` (RHEL family) or ``journalctl -o short-iso`` output, in
either the classic ``Nov 17 22:01:02 host prog[pid]: message`` form or the
ISO-8601 high-precision form. Recognized events:

* sshd ``Failed <method> for [invalid user] U from IP``, ``Invalid user U from IP``
  and ``Accepted <method> for U from IP``;
* sudo ``N incorrect password attempts`` and ``user NOT in sudoers``;
* ``useradd`` new accounts, and ``usermod``/``gpasswd`` additions to
  privileged groups (sudo, wheel, admin, root and root-equivalent groups).

Findings (all heuristics for review, never a verdict):

``AUTH_SUCCESS_AFTER_FAILURES`` CRITICAL  a login succeeded from an address
                                          that had many recent failures;
``AUTH_FAILURE_BURST``          HIGH      many failed logins from one address;
``PASSWORD_SPRAY``              HIGH      one address tried many usernames;
``SUDO_DENIED``                 HIGH      a user not in sudoers tried sudo;
``PRIVILEGE_GRANT``             HIGH      an account joined a privileged group;
``SUDO_FAILURES``               MEDIUM    repeated wrong sudo passwords;
``ACCOUNT_CREATED``             MEDIUM    a new local account appeared;
``LURE_FOLLOWED``               CRITICAL  a login was tried as an agent lure's account (``canary plant --lure``):
                                          something read a note written for automated agents and acted on it.

Usernames come from attackers and are untrusted text: they are bounded,
stripped of control characters and only ever reported as data.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
import stat
import sys
from typing import Any, BinaryIO, Iterable

from .validation import ValidationError

SCHEMA = "megalodon-auth-review-v1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_TRACKED_KEYS = 50_000
MAX_FINDINGS = 500
MAX_PENDING_INVALID = 4096
MAX_USER_CHARS = 64
MAX_USERS_SHOWN = 10
MAX_PER_SOURCE = 4096  # counts above this are reported as "at least"
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "adm", "docker", "lxd",
                               "libvirt", "disk", "shadow"})
SEVERITY = {
    "AUTH_SUCCESS_AFTER_FAILURES": "CRITICAL", "AUTH_FAILURE_BURST": "HIGH",
    "PASSWORD_SPRAY": "HIGH", "SUDO_DENIED": "HIGH", "PRIVILEGE_GRANT": "HIGH",
    "SUDO_FAILURES": "MEDIUM", "ACCOUNT_CREATED": "MEDIUM", "LURE_FOLLOWED": "CRITICAL",
}
_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
NETWORK_RULES = frozenset({"AUTH_FAILURE_BURST", "PASSWORD_SPRAY", "AUTH_SUCCESS_AFTER_FAILURES", "LURE_FOLLOWED"})
ATTACK = {
    "AUTH_SUCCESS_AFTER_FAILURES": ["T1110", "T1078"], "AUTH_FAILURE_BURST": ["T1110.001"],
    "PASSWORD_SPRAY": ["T1110.003"], "SUDO_DENIED": ["T1548.003"],
    "SUDO_FAILURES": ["T1548.003"], "PRIVILEGE_GRANT": ["T1098"],
    "ACCOUNT_CREATED": ["T1136.001"], "LURE_FOLLOWED": ["T1078", "T1552.001"],
}

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CLASSIC = re.compile(
    r"(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[\w.\-/()]+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)")
_ISO = re.compile(
    r"(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})) "
    r"(?P<host>\S+) (?P<prog>[\w.\-/()]+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)")
_FAILED = re.compile(
    r"Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9A-Fa-f:.]+)(?: port \d+)?$")
_ACCEPTED = re.compile(
    r"Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_SUDO_WRONG = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<n>\d+) )?incorrect password attempts?")
_SUDO_DENIED = re.compile(r"^\s*(?P<user>\S+) : (?:user )?NOT in sudoers")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+), UID=(?P<uid>\d+)")
_USERMOD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_GPASSWD = re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")


@dataclass(frozen=True)
class AuthReviewSettings:
    failure_window_seconds: int = 600
    failure_threshold: int = 6
    spray_window_seconds: int = 3600
    spray_distinct_users: int = 4
    success_lookback_seconds: int = 3600
    success_min_failures: int = 5
    sudo_window_seconds: int = 600
    sudo_failure_threshold: int = 3
    cooldown_seconds: int = 3600

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
                raise ValueError(f"auth review {name} must be an integer from 1 to 86400")
        if self.failure_threshold < 2 or self.spray_distinct_users < 2:
            raise ValueError("auth review thresholds must be at least 2")


def _clean_user(value: str) -> str:
    text = "".join(ch for ch in value if ch.isprintable() and not ch.isspace())
    return (text or "(empty)")[:MAX_USER_CHARS]


def _address(text: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return str(parsed)


class _SourceState:
    """Three independently pruned windows; every structure is capped."""

    __slots__ = ("burst", "recent", "users")

    def __init__(self) -> None:
        self.burst: deque[datetime] = deque(maxlen=MAX_PER_SOURCE)
        self.recent: deque[datetime] = deque(maxlen=MAX_PER_SOURCE)
        self.users: OrderedDict[str, datetime] = OrderedDict()

    def add(self, when: datetime, user: str) -> None:
        self.burst.append(when)
        self.recent.append(when)
        self.users.pop(user, None)
        self.users[user] = when
        while len(self.users) > MAX_PER_SOURCE:
            self.users.popitem(last=False)

    def prune(self, when: datetime, settings: "AuthReviewSettings") -> None:
        for window, seconds in ((self.burst, settings.failure_window_seconds),
                                (self.recent, settings.success_lookback_seconds)):
            cutoff = when - timedelta(seconds=seconds)
            while window and window[0] < cutoff:
                window.popleft()
        cutoff = when - timedelta(seconds=settings.spray_window_seconds)
        while self.users and next(iter(self.users.values())) < cutoff:
            self.users.popitem(last=False)

    def users_shown(self) -> list[str]:
        return sorted(self.users)[:MAX_USERS_SHOWN]


class _Clock:
    """Turn classic syslog stamps (no year, local time) into aware datetimes."""

    def __init__(self, reference: datetime, zone) -> None:
        self.reference = reference
        self.zone = zone

    def classic(self, mon: str, day: str, clock: str) -> datetime | None:
        month = _MONTHS.get(mon)
        if month is None:
            return None
        hour, minute, second = (int(part) for part in clock.split(":"))
        year = self.reference.year
        try:
            stamp = datetime(year, month, int(day), hour, minute, second, tzinfo=self.zone)
            # A December line read in January belongs to the previous year.
            if stamp > self.reference + timedelta(days=1):
                stamp = stamp.replace(year=year - 1)
        except ValueError:
            return None
        return stamp

    @staticmethod
    def iso(text: str) -> datetime | None:
        text = text.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", text):
            text = text[:-2] + ":" + text[-2:]
        main, _, rest = text.partition(".")
        if rest:
            digits = re.match(r"\d+", rest).group(0)
            text = main + "." + digits[:6].ljust(6, "0") + rest[len(digits):]
        try:
            stamp = datetime.fromisoformat(text)
        except ValueError:
            return None
        return stamp if stamp.tzinfo is not None else None


class AuthReviewer:
    def __init__(self, settings: AuthReviewSettings | None = None, *,
                 reference: datetime | None = None, zone=None, on_finding=None, lure_users=()) -> None:
        self.settings = settings or AuthReviewSettings()
        # Called with every finding as it is made, before the report's display cap: a reader that must see all of
        # them (the response engine) takes them here, not from the bounded report.
        self.on_finding = on_finding
        # Agent lures' accounts: any login tried as one is LURE_FOLLOWED, whatever came before it.
        self.lure_users = frozenset(_clean_user(str(user)).casefold() for user in lure_users)
        reference = reference or datetime.now(timezone.utc)
        self.clock = _Clock(reference.astimezone(zone) if zone else reference.astimezone(),
                            zone or reference.astimezone().tzinfo)
        # Per source: burst-window stamps, lookback-window stamps, user -> last seen.
        self.failures: OrderedDict[str, _SourceState] = OrderedDict()
        self.sudo: OrderedDict[str, deque[datetime]] = OrderedDict()
        self.pending_invalid: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self.emitted: OrderedDict[tuple[str, str], datetime] = OrderedDict()
        # Retained findings are bounded for display; totals and attacker sources
        # are tracked for every emitted finding so the cap never hides an attack.
        self._retained: list[tuple[int, dict[str, Any]]] = []
        self._sequence = 0
        self.severity_totals: Counter[str] = Counter()
        self.sources: OrderedDict[str, str] = OrderedDict()
        self.truncated = False
        self.stats = Counter()
        self.failures_by_source: Counter[str] = Counter()
        self.first: datetime | None = None
        self.last: datetime | None = None

    # ---------------------------------------------------------------- input
    def feed(self, lines: Iterable[bytes]) -> None:
        for raw in lines:
            self.stats["lines"] += 1
            if len(raw) > MAX_LINE_BYTES:
                self.stats["oversized_lines"] += 1
                continue
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            self._line(text)

    def _line(self, text: str) -> None:
        match = _ISO.match(text)
        if match:
            when = self.clock.iso(match["stamp"])
        else:
            match = _CLASSIC.match(text)
            when = self.clock.classic(match["mon"], match["day"], match["time"]) if match else None
        if match is None:
            self.stats["unrecognized_lines"] += 1
            return
        if when is None:
            self.stats["invalid_timestamps"] += 1
            return
        if self.last is not None and when < self.last:
            # Concatenated rotations can interleave; keep windows monotonic.
            self.stats["out_of_order"] += 1
            when = self.last
        self.first = self.first or when
        self.last = when
        program = match["prog"].rsplit("/", 1)[-1]
        message, pid = match["msg"], match["pid"] or ""
        if program.startswith("sshd"):
            self._sshd(when, pid, message)
        elif program == "sudo":
            self._sudo(when, message)
        elif program in {"useradd", "adduser"}:
            found = _USERADD.search(message)
            if found:
                self.stats["accounts_created"] += 1
                user = _clean_user(found["user"])
                self._emit("ACCOUNT_CREATED", user, when, user,
                           f"New local account {user} (UID {found['uid']}) was created.",
                           {"user": user, "uid": int(found["uid"])})
        elif program in {"usermod", "gpasswd"}:
            found = _USERMOD.search(message) or _GPASSWD.search(message)
            if found and found["group"] in PRIVILEGED_GROUPS:
                self.stats["privilege_grants"] += 1
                user, group = _clean_user(found["user"]), found["group"]
                self._emit("PRIVILEGE_GRANT", f"{user}:{group}", when, user,
                           f"Account {user} was added to privileged group {group}.",
                           {"user": user, "group": group})

    # ---------------------------------------------------------------- sshd
    def _sshd(self, when: datetime, pid: str, message: str) -> None:
        found = _FAILED.search(message)
        if found:
            address = _address(found["ip"])
            if address is None:
                return
            user = _clean_user(found["user"])
            pending = self.pending_invalid.pop(pid, None) if pid else None
            if found["invalid"] and pending == (user, address):
                return  # already counted from the matching "Invalid user" line
            self._failure(when, address, user)
            return
        found = _INVALID.search(message)
        if found:
            address = _address(found["ip"])
            if address is None:
                return
            user = _clean_user(found["user"])
            if pid:
                self.pending_invalid[pid] = (user, address)
                while len(self.pending_invalid) > MAX_PENDING_INVALID:
                    self.pending_invalid.popitem(last=False)
            self._failure(when, address, user)
            return
        found = _ACCEPTED.search(message)
        if found:
            address = _address(found["ip"])
            if address is None:
                return
            self._accepted(when, address, _clean_user(found["user"]), found["method"])

    def _accepted(self, when: datetime, address: str, user: str, method: str) -> None:
        self.stats["successful_logins"] += 1
        # Accepted as a lure's account: the account exists after all, and someone has it.
        self._lure(when, address, user, accepted=True)
        settings = self.settings
        state = self.failures.get(address)
        if state is None:
            return
        state.prune(when, settings)
        prior = len(state.recent)
        if prior >= settings.success_min_failures:
            self._emit(
                "AUTH_SUCCESS_AFTER_FAILURES", f"{address}:{user}", when, address,
                f"Login as {user} via {method} succeeded from {address} after "
                f"{prior}{'+' if prior >= MAX_PER_SOURCE else ''} failed attempts in the "
                f"previous {settings.success_lookback_seconds}s.",
                {"source": address, "user": user, "method": method,
                 "prior_failures": prior, "usernames_tried": state.users_shown()},
            )

    def _lure(self, when: datetime, address: str, user: str, *, accepted: bool) -> None:
        if user.casefold() not in self.lure_users:
            return
        outcome = "accepted: the account exists, so check it at once" if accepted else "refused"
        # Accepted and refused are kept apart: a login let in right after refused tries is never held back as a repeat.
        self._emit("LURE_FOLLOWED", f"{address}:{user.casefold()}:{'accepted' if accepted else 'refused'}", when,
                   address, f"{address} tried to log in as {user}, the account an agent lure names ({outcome}).",
                   {"source": address, "user": user, "outcome": outcome, "accepted": accepted})

    def _failure(self, when: datetime, address: str, user: str) -> None:
        settings = self.settings
        self._lure(when, address, user, accepted=False)
        self.stats["failed_logins"] += 1
        self.failures_by_source[address] += 1
        state = self.failures.pop(address, None) or _SourceState()
        self.failures[address] = state  # most recently used last
        state.add(when, user)
        state.prune(when, settings)
        while len(self.failures) > MAX_TRACKED_KEYS:
            self.failures.popitem(last=False)
        burst = len(state.burst)
        if burst >= settings.failure_threshold:
            self._emit(
                "AUTH_FAILURE_BURST", address, when, address,
                f"{burst}{'+' if burst >= MAX_PER_SOURCE else ''} failed logins from {address} "
                f"within {settings.failure_window_seconds}s.",
                {"source": address, "failures": burst,
                 "threshold": settings.failure_threshold,
                 "window_seconds": settings.failure_window_seconds,
                 "usernames_tried": state.users_shown()},
            )
        distinct = len(state.users)
        if distinct >= settings.spray_distinct_users:
            self._emit(
                "PASSWORD_SPRAY", address, when, address,
                f"{address} tried {distinct} different usernames within "
                f"{settings.spray_window_seconds}s.",
                {"source": address, "distinct_users": distinct,
                 "threshold": settings.spray_distinct_users,
                 "window_seconds": settings.spray_window_seconds,
                 "usernames_tried": state.users_shown()},
            )

    # ---------------------------------------------------------------- sudo
    def _sudo(self, when: datetime, message: str) -> None:
        found = _SUDO_DENIED.search(message)
        if found:
            self.stats["sudo_denied"] += 1
            user = _clean_user(found["user"])
            self._emit("SUDO_DENIED", user, when, user,
                       f"{user}, who is not permitted to use sudo, tried to run a command as root.",
                       {"user": user})
            return
        found = _SUDO_WRONG.search(message)
        if not found:
            return
        user = _clean_user(found["user"])
        attempts = min(int(found["n"] or 1), 100)
        self.stats["sudo_failures"] += attempts
        settings = self.settings
        window = self.sudo.pop(user, None) or deque()
        self.sudo[user] = window
        for _ in range(attempts):
            window.append(when)
        cutoff = when - timedelta(seconds=settings.sudo_window_seconds)
        while window and window[0] < cutoff:
            window.popleft()
        while len(window) > settings.sudo_failure_threshold:
            window.popleft()
        while len(self.sudo) > MAX_TRACKED_KEYS:
            self.sudo.popitem(last=False)
        if len(window) >= settings.sudo_failure_threshold:
            self._emit("SUDO_FAILURES", user, when, user,
                       f"{user} entered a wrong sudo password {len(window)} or more times within "
                       f"{settings.sudo_window_seconds}s.",
                       {"user": user, "threshold": settings.sudo_failure_threshold,
                        "window_seconds": settings.sudo_window_seconds})

    # ------------------------------------------------------------- findings
    def _emit(self, rule: str, key: str, when: datetime, subject: str,
              message: str, evidence: dict[str, Any]) -> None:
        marker = (rule, key)
        previous = self.emitted.get(marker)
        if previous is not None and when - previous < timedelta(seconds=self.settings.cooldown_seconds):
            return
        self.emitted[marker] = when
        self.emitted.move_to_end(marker)
        while len(self.emitted) > MAX_TRACKED_KEYS:
            self.emitted.popitem(last=False)
        severity = SEVERITY[rule]
        self.severity_totals[severity] += 1
        source = evidence.get("source")
        if rule in NETWORK_RULES and source:
            parsed = ipaddress.ip_address(source)
            if not (parsed.is_loopback or parsed.is_unspecified) and source not in self.sources:
                self.sources[source] = f"auth-review {rule}"
                while len(self.sources) > MAX_TRACKED_KEYS:
                    self.sources.popitem(last=False)
        finding = {
            "rule_id": rule, "severity": severity, "observed_at": when.isoformat(),
            "subject": subject, "message": message, "evidence": evidence,
            "attack": ATTACK[rule],
            # What makes this finding itself: an account joining two groups at once is two findings.
            "identity": key,
        }
        if self.on_finding is not None:
            self.on_finding(finding)
        self._sequence += 1
        if len(self._retained) < MAX_FINDINGS:
            self._retained.append((self._sequence, finding))
            return
        self.truncated = True
        # Keep the most severe: replace the newest of the least severe retained findings.
        worst = max(range(len(self._retained)),
                    key=lambda i: (_RANK[self._retained[i][1]["severity"]], self._retained[i][0]))
        if _RANK[severity] < _RANK[self._retained[worst][1]["severity"]]:
            self._retained[worst] = (self._sequence, finding)

    @property
    def findings(self) -> list[dict[str, Any]]:
        return [finding for _, finding in sorted(self._retained, key=lambda item: item[0])]

    def report(self, source: str) -> dict[str, Any]:
        severities = self.severity_totals
        return {
            "schema": SCHEMA,
            "source": source,
            "window": {"start": self.first.isoformat() if self.first else None,
                       "end": self.last.isoformat() if self.last else None},
            "input": {key: self.stats[key] for key in (
                "lines", "unrecognized_lines", "oversized_lines", "invalid_timestamps",
                "out_of_order")},
            "observed": {key: self.stats[key] for key in (
                "failed_logins", "successful_logins", "sudo_failures", "sudo_denied",
                "accounts_created", "privilege_grants")},
            "top_failing_sources": [
                {"source": address, "failures": count}
                for address, count in self.failures_by_source.most_common(10)
            ],
            "severity_counts": {name: severities.get(name, 0)
                                for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "findings": self.findings,
            "truncated": self.truncated,
            "settings": dict(self.settings.__dict__),
            "limitations": [
                "Only lines in the supplied log are reviewed; rotated or forwarded logs may be missing.",
                "Classic syslog lines carry no year or zone; local time and the current year are assumed.",
                "A failure count is not proof of an attack, and a quiet log is not proof of safety.",
                "Usernames are attacker-supplied text and are shown only as bounded data.",
            ],
            "network_access_performed": False,
            "action_status": "not_attempted",
        }

    def attacker_sources(self) -> list[tuple[str, str]]:
        """Addresses behind network-attributable findings, for an optional watchlist."""
        return sorted(self.sources.items())


def read_lines(path: str) -> Iterable[bytes]:
    """Yield bounded lines from a regular file, or stdin when ``path`` is ``-``."""
    if path == "-":
        stream: BinaryIO = sys.stdin.buffer
        total = 0
        for line in stream:
            total += len(line)
            if total > MAX_INPUT_BYTES:
                raise ValidationError("auth log input exceeds the 64 MiB limit")
            yield line
        return
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        hint = " (reading auth logs usually needs membership in the adm group)" \
            if exc.errno in {1, 13} else ""
        raise ValidationError(f"auth log cannot be opened: {exc.strerror}{hint}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("auth log must be a regular file or '-' for stdin")
        if info.st_size > MAX_INPUT_BYTES:
            raise ValidationError("auth log exceeds the 64 MiB limit; review a rotated slice")
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        total = 0
        for line in stream:
            total += len(line)
            if total > MAX_INPUT_BYTES:
                raise ValidationError("auth log grew past the 64 MiB limit while reading")
            yield line


JOURNALCTL = ("/usr/bin/journalctl", "/bin/journalctl")
JOURNAL_FACILITIES = ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")      # auth and authpriv: what auth.log holds
JOURNAL_TIMEOUT = 120


def read_journal(since: datetime, notes: list[str]) -> list[bytes]:
    """The systemd journal's auth and authpriv messages since ``since``, as lines ``review`` reads, bounded as a log
    file is. journalctl only reads. What it warns of (no journal files; only this user's own messages) is added to
    ``notes``: the review is then partial, not failed."""
    import subprocess
    import tempfile
    import threading
    program = next((path for path in JOURNALCTL if os.path.isfile(path)), None)
    if program is None:
        raise ValidationError("the journal cannot be read: journalctl is not installed")
    argv = [program, "--no-pager", "--utc", "-o", "short-iso-precise", f"--since=@{int(since.timestamp())}",
            *JOURNAL_FACILITIES]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "", "SYSTEMD_LESS": ""}
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors, env=env,
                                   close_fds=True)
        timer = threading.Timer(JOURNAL_TIMEOUT, process.kill)
        timer.start()
        lines: list[bytes] = []
        total = 0
        try:
            for line in process.stdout:
                total += len(line)
                if total > MAX_INPUT_BYTES:
                    raise ValidationError("the journal's auth messages exceed the 64 MiB limit")
                lines.append(line)
        finally:
            if total > MAX_INPUT_BYTES:
                process.kill()
            process.stdout.close()
            code = process.wait()
            timer.cancel()
        errors.seek(0)
        said = errors.read(4096).decode("utf-8", "replace")
    if code != 0:
        if code < 0:
            raise ValidationError(f"journalctl did not finish within {JOURNAL_TIMEOUT} s")
        first = next((line.strip() for line in said.splitlines() if line.strip()), f"exit status {code}")
        raise ValidationError(f"the journal cannot be read: {first[:200]}")
    if "No journal files were found" in said:
        notes.append("the journal holds no files here: journald keeps none, or keeps them where this user cannot "
                     "see them")
    elif "not seeing messages from other users and the system" in said:
        notes.append("the journal shows only this user's own messages, not logins: run as root, or in the adm or "
                     "systemd-journal group")
    return lines


def review(lines: Iterable[bytes], *, source: str, settings: AuthReviewSettings | None = None,
           reference: datetime | None = None, zone=None, on_finding=None,
           lure_users=()) -> tuple[dict[str, Any], AuthReviewer]:
    reviewer = AuthReviewer(settings, reference=reference, zone=zone, on_finding=on_finding, lure_users=lure_users)
    reviewer.feed(lines)
    return reviewer.report(source), reviewer
