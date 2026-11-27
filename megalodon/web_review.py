"""Web server access logs: requests for the page an agent lure names.

An agent lure (``megalodon canary plant --lure``) is a note written as instructions to automated agents and AI
assistants. Besides an SSH account, it names a page of this site: a random path that no page links to, given as a
path and a code in a sentence. A crawler that follows links never builds it; an AI agent that reads the note and
acts on it does. A request for that path is ``LURE_FOLLOWED`` (CRITICAL), whatever the server answered.

Reads nginx's and Apache's default access log formats (``combined`` and ``common``): the client address first, the
time in brackets, then the quoted request. Lines in other formats are counted as unrecognized and skipped. Only
requests for a lure's page are reported: this is not a general web attack detector.

Read only, bounded like the auth log review: input up to 64 MiB, lines up to 8 KiB, at most 500 findings. One
address asking for the same page again within an hour is one finding.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
import stat
import sys
from typing import Any, BinaryIO, Iterable
from urllib.parse import unquote, urlsplit

from .validation import ValidationError

SCHEMA = "megalodon-web-review-v1"
RULE = "LURE_FOLLOWED"
SEVERITY = "CRITICAL"
ATTACK = ["T1078", "T1552.001"]
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024
MAX_FINDINGS = 500
MAX_TRACKED_KEYS = 50_000
COOLDOWN_SECONDS = 3600
WEB_LOGS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log")

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_LINE = re.compile(
    r'(?P<ip>[0-9A-Fa-f:.]+) \S+ \S+ '
    r'\[(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<hms>\d{2}:\d{2}:\d{2}) (?P<zone>[+-]\d{4})\] '
    r'"(?P<method>[A-Z]{1,16}) (?P<target>[^ "]{1,4096})(?: [^"]*)?"')


def _when(match: re.Match[str]) -> datetime | None:
    month = _MONTHS.get(match["mon"])
    if month is None:
        return None
    try:
        hours, minutes, seconds = (int(part) for part in match["hms"].split(":"))
        zone = match["zone"]
        offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5]))
        when = datetime(int(match["year"]), month, int(match["day"]), hours, minutes, seconds,
                        tzinfo=timezone(offset if zone[0] == "+" else -offset))
    except ValueError:
        return None
    return when.astimezone(timezone.utc)


def _page(target: str) -> str:
    """The path a request asked for: of an absolute URI too, without its query, percent-decoded, in lower case."""
    try:
        path = urlsplit(target).path if "://" in target[:16] else target.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        return ""
    return unquote(path).casefold()


class WebReviewer:
    def __init__(self, lure_pages: Iterable[str] = (), *, on_finding=None) -> None:
        self.lure_pages = tuple(sorted({str(page).casefold().rstrip("/") for page in lure_pages if page}))
        self.on_finding = on_finding
        self.stats: Counter[str] = Counter()
        self.emitted: OrderedDict[tuple[str, str], datetime] = OrderedDict()
        self.findings: list[dict[str, Any]] = []
        self.truncated = False
        self.first: datetime | None = None
        self.last: datetime | None = None

    def feed(self, lines: Iterable[bytes]) -> None:
        for raw in lines:
            self.stats["lines"] += 1
            if len(raw) > MAX_LINE_BYTES:
                self.stats["oversized_lines"] += 1
                continue
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            match = _LINE.match(text)
            if match is None:
                self.stats["unrecognized_lines"] += 1
                continue
            when = _when(match)
            if when is None:
                self.stats["invalid_timestamps"] += 1
                continue
            try:
                address = str(ipaddress.ip_address(match["ip"]))
            except ValueError:
                self.stats["unrecognized_lines"] += 1
                continue
            self.first = min(self.first, when) if self.first else when
            self.last = max(self.last, when) if self.last else when
            self._request(when, address, match["method"], match["target"])

    def _request(self, when: datetime, address: str, method: str, target: str) -> None:
        self.stats["requests"] += 1
        path = _page(target)
        page = next((p for p in self.lure_pages if path == p or path.startswith(p + "/")), None)
        if page is None:
            return
        key = (address, page)
        previous = self.emitted.get(key)
        if previous is not None and timedelta(0) <= when - previous < timedelta(seconds=COOLDOWN_SECONDS):
            return
        self.emitted[key] = when
        self.emitted.move_to_end(key)
        while len(self.emitted) > MAX_TRACKED_KEYS:
            self.emitted.popitem(last=False)
        finding = {
            "rule_id": RULE, "severity": SEVERITY, "observed_at": when.isoformat(), "subject": address,
            "message": f"{address} asked this site for {page}, the page an agent lure names ({method}).",
            "evidence": {"source": address, "page": page, "method": method, "requested": target[:256]},
            "attack": ATTACK, "identity": f"{address}:{page}",
        }
        if self.on_finding is not None:
            self.on_finding(finding)
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(finding)
        else:
            self.truncated = True

    def report(self, source: str) -> dict[str, Any]:
        return {
            "schema": SCHEMA, "source": source,
            "window": {"start": self.first.isoformat() if self.first else None,
                       "end": self.last.isoformat() if self.last else None},
            "input": {key: self.stats[key] for key in
                      ("lines", "requests", "unrecognized_lines", "oversized_lines", "invalid_timestamps")},
            "lure_pages_watched": len(self.lure_pages),
            "severity_counts": {"CRITICAL": len(self.findings), "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "findings": self.findings, "truncated": self.truncated,
            "limitations": [
                "Only requests for an agent lure's page are reported; this is not a general web attack detector.",
                "Only nginx's and Apache's combined and common formats are read; other lines are skipped.",
                "The address is the one the server logged: behind a proxy, it is the proxy's.",
            ],
        }


def read_lines(path: str) -> Iterable[bytes]:
    """Bounded lines from a regular file, or stdin when ``path`` is ``-``."""
    if path == "-":
        stream: BinaryIO = sys.stdin.buffer
        total = 0
        for line in stream:
            total += len(line)
            if total > MAX_INPUT_BYTES:
                raise ValidationError("web log input exceeds the 64 MiB limit")
            yield line
        return
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        hint = " (reading web logs usually needs membership in the adm group)" if exc.errno in {1, 13} else ""
        raise ValidationError(f"web log cannot be opened: {exc.strerror}{hint}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("web log must be a regular file or '-' for stdin")
        if info.st_size > MAX_INPUT_BYTES:
            raise ValidationError("web log exceeds the 64 MiB limit; review a rotated slice")
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        total = 0
        for line in stream:
            total += len(line)
            if total > MAX_INPUT_BYTES:
                raise ValidationError("web log grew past the 64 MiB limit while reading")
            yield line


def review(lines: Iterable[bytes], *, source: str, lure_pages: Iterable[str] = (),
           on_finding=None) -> tuple[dict[str, Any], WebReviewer]:
    reviewer = WebReviewer(lure_pages, on_finding=on_finding)
    reviewer.feed(lines)
    return reviewer.report(source), reviewer
