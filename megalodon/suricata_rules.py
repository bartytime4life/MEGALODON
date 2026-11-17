"""Explicit, additive ET Open staging for an already configured passive sensor.

The embedded helper is sent to the fixed system interpreter through pkexec.
Only a closed action, an existing interface, one CIDR, or a generation token
crosses that boundary. Snapshot reads the dated in-memory receipt only.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from ipaddress import ip_network
import json
import re
from threading import Lock

from . import execution_boundary
from .companion_automation import _run_fixed

SCHEMA = "megalodon-suricata-rules-v1"
MAX_RECEIPT = 8192
MESSAGES = {
    "AUTH_REQUIRED": "System authorization and an ordinary requesting account are required.",
    "BUSY": "Another rules operation is running.",
    "UNSAFE_PATH": "A required file or parent has unsafe ownership, permissions, type, or links; review the installed configuration.",
    "CONFIG_UNSUPPORTED": "The base configuration has unresolved includes, paths, or executable extensions; review it before staging.",
    "SERVICE_UNSUPPORTED": "The service has an unsupported unit or override; review its configuration before staging.",
    "RULE_UNSUPPORTED": "Rules contain an unsupported action, external dependency, or ambiguous syntax; existing rules were preserved.",
    "RULE_CONFLICT": "Candidate and existing rules have duplicate signature identities; resolve the conflict explicitly.",
    "UPDATE_FAILED": "The isolated ET Open update failed; the active rules were not replaced.",
    "TEST_FAILED": "Native Suricata configuration testing failed; the candidate was not activated.",
    "STALE_GENERATION": "The engine, configuration, rules, or service changed; stage a fresh generation.",
    "PENDING_RECOVERY": "An interrupted activation needs explicit rollback before another change.",
    "NO_ROLLBACK": "No previous managed activation is available to roll back.",
    "RESTART_FAILED": "Activation failed and the previous service configuration was restored.",
    "ROLLBACK_FAILED": "Service rollback could not be verified; inspect the service before proceeding.",
    "LIMIT": "A file, process, generation count, or resource bound was exceeded.",
    "TIMEOUT": "The bounded helper operation timed out; use Check and review any pending recovery.",
    "DEPENDENCY_MISSING": "The installed engine, updater, service tools, or system PyYAML dependency is unavailable.",
    "HELPER_FAILED": "The rules operation did not return a valid receipt; use Check before assuming any service state.",
}


def valid_home_net(value):
    if type(value) is not str or len(value) > 49 or "/" not in value:
        raise ValueError("Choose one canonical network CIDR for the capture position.")
    try:
        network = ip_network(value, strict=True)
    except ValueError:
        raise ValueError("Choose one canonical network CIDR for the capture position.") from None
    if str(network) != value:
        raise ValueError("Choose one canonical network CIDR for the capture position.")
    return value


def _interface(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", value):
        raise ValueError("Choose an existing local capture interface.")
    return value


def _generation(value):
    if type(value) is not str or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError("Choose a staged generation token.")
    return value


def validate_scope(interface, home_net):
    """Validate the closed request shape; the privileged helper checks existence."""
    execution_boundary.require_effects_allowed()
    return _interface(interface), valid_home_net(home_net)


# This program has no import of repository code or operator-selected path.
# Tests compile its definitions into an unprivileged fixture namespace, replace
# all native effects, and never invoke its main entry point or pkexec.
ROOT_PROGRAM = r'''
import base64, fcntl, grp, hashlib, ipaddress, json, os, re, resource
import selectors, signal, socket, stat, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "megalodon-suricata-rules-v1"
ROOT = Path("/var/lib/megalodon-suricata")
GENS = ROOT / "generations"
BASE = Path("/etc/suricata/suricata.yaml")
DROP_DIR = Path("/etc/systemd/system/suricata.service.d")
DROP = DROP_DIR / "zzzz-megalodon-rules.conf"
ENGINE = Path("/usr/bin/suricata")
UPDATER = Path("/usr/bin/suricata-update")
SYSTEMCTL = Path("/usr/bin/systemctl")
UNIT = Path("/usr/lib/systemd/system/suricata.service")
LOCAL_UNIT = Path("/etc/systemd/system/suricata.service")
LOG = Path("/var/log/suricata")
ANCHOR = Path("/")
TRUSTED_UID = 0
SOURCE = "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz"
FILE_LIMIT = 64 * 1024 * 1024
TREE_LIMIT = 256 * 1024 * 1024
TOTAL_RULES = 200000
DEADLINE = time.monotonic() + 330

class Fault(Exception):
    pass

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def stamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def safe(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise Fault("UNSAFE_PATH")
    try:
        relative = path.relative_to(ANCHOR)
        current = ANCHOR
        for part in (None, *relative.parts):
            if part is not None:
                current = current / part
            info = current.lstat()
            is_dir = current != path or directory
            if (info.st_uid != TRUSTED_UID or info.st_mode & 0o022
                    or stat.S_ISLNK(info.st_mode)
                    or (not stat.S_ISDIR(info.st_mode) if is_dir else
                        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
                raise Fault("UNSAFE_PATH")
        return info
    except (OSError, ValueError):
        raise Fault("UNSAFE_PATH") from None

def read(path, maximum=FILE_LIMIT):
    before = safe(path)
    if before.st_size > maximum:
        raise Fault("LIMIT")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Fault("UNSAFE_PATH")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        if (len(raw) > maximum or len(raw) != before.st_size
                or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                   (before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise Fault("UNSAFE_PATH")
        return raw
    finally:
        os.close(fd)

def mkdir(path, mode=0o700):
    safe(Path(path).parent, True)
    if not Path(path).exists():
        Path(path).mkdir(mode=mode)
    safe(path, True)

def write(path, raw, mode=0o600):
    path = Path(path)
    safe(path.parent, True)
    if path.exists() or path.is_symlink():
        safe(path)
    temporary = path.parent / (".write-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        if temporary.exists():
            temporary.unlink()

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Fault("STALE_GENERATION")
        result[key] = value
    return result

def load(path):
    try:
        return json.loads(read(path, 65536), object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise Fault("STALE_GENERATION") from None

def save(path, value):
    write(path, json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())

def tree_bound(root):
    total = count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise Fault("UNSAFE_PATH")
            count += 1
            total += info.st_size
            if count > 512 or total > TREE_LIMIT or info.st_size > FILE_LIMIT:
                raise Fault("LIMIT")

def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    os.umask(0o077)

def run(argv, timeout=30, cwd=None, maximum=2 * 1024 * 1024):
    timeout=min(timeout,DEADLINE-time.monotonic())
    if timeout<=0:
        raise Fault("TIMEOUT")
    safe(Path(argv[0]))
    directory = Path(cwd or ROOT)
    safe(directory, True)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, cwd=directory, start_new_session=True, preexec_fn=limits,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C", "LC_ALL":"C",
             "SC_LOG_LEVEL":"Error", "TMPDIR":str(directory)})
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Fault("TIMEOUT")
                tree_bound(directory)
                for key, _ in selector.select(min(0.25, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > maximum:
                            raise Fault("LIMIT")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Fault("TIMEOUT")
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise Fault("TIMEOUT") from None
        return bytes(output), code
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()

def yaml_document(raw):
    try:
        import yaml
    except ImportError:
        raise Fault("DEPENDENCY_MISSING") from None
    class Strict(yaml.SafeLoader):
        pass
    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if type(key) is not str or key in result or key == "<<":
                raise Fault("CONFIG_UNSUPPORTED")
            result[key] = loader.construct_object(value_node)
        return result
    Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        # Aliases can be recursive or expand analysis unexpectedly; refuse them.
        if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken))
               for token in yaml.scan(raw)):
            raise Fault("CONFIG_UNSUPPORTED")
        document = yaml.load(raw, Loader=Strict)
        if type(document) is not dict:
            raise Fault("CONFIG_UNSUPPORTED")
        return document
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise Fault("CONFIG_UNSUPPORTED") from None

def rules(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Fault("RULE_UNSUPPORTED") from None
    identities = set()
    banned = {"lua", "luajit", "luaxform", "filestore", "replace", "dataset", "datarep",
              "filemd5", "filesha1", "filesha256", "bypass", "tag", "react", "resp"}
    pending = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pending += line[:-1] if line.endswith("\\") else line
        if len(pending) > 131072:
            raise Fault("LIMIT")
        if line.endswith("\\"):
            continue
        if not re.match(r"^alert\s+", pending) or not pending.endswith(")") or "(" not in pending:
            raise Fault("RULE_UNSUPPORTED")
        body = pending.split("(", 1)[1][:-1]
        options = []; current = ""; quoted = escaped = False
        for char in body:
            if escaped:
                current += char; escaped = False; continue
            if char == "\\":
                current += char; escaped = True; continue
            if char == '"':
                quoted = not quoted
            if char == ";" and not quoted:
                options.append(current.strip()); current = ""
            else:
                current += char
        if quoted or escaped or current.strip():
            raise Fault("RULE_UNSUPPORTED")
        identifiers = {}
        for option in options:
            keyword, _, value = option.partition(":")
            keyword = keyword.strip().lower()
            if not re.fullmatch(r"[a-z0-9_.-]+", keyword) or keyword in banned:
                raise Fault("RULE_UNSUPPORTED")
            if keyword in {"sid", "gid"}:
                if keyword in identifiers or not value.strip().isdigit():
                    raise Fault("RULE_UNSUPPORTED")
                number = int(value.strip())
                if not 1 <= number <= 4294967295:
                    raise Fault("RULE_UNSUPPORTED")
                identifiers[keyword] = number
        if "sid" not in identifiers:
            raise Fault("RULE_UNSUPPORTED")
        identity = (identifiers.get("gid", 1), identifiers["sid"])
        if identity in identities:
            raise Fault("RULE_CONFLICT")
        identities.add(identity)
        if len(identities) > TOTAL_RULES:
            raise Fault("LIMIT")
        pending = ""
    if pending:
        raise Fault("RULE_UNSUPPORTED")
    return identities

def source_inputs():
    base = read(BASE, 2 * 1024 * 1024)
    config = yaml_document(base)
    if "include" in config or config.get("plugins") or config.get("lua"):
        raise Fault("CONFIG_UNSUPPORTED")
    # The supported profile excludes unbound external scripts/data inputs.
    def inspect(value, depth=0):
        if depth > 24:
            raise Fault("CONFIG_UNSUPPORTED")
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"include", "copy-mode", "copy-iface", "luajit", "lua",
                           "load", "save", "state"} and child not in (None, False, "no", ""):
                    raise Fault("CONFIG_UNSUPPORTED")
                inspect(child, depth+1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, depth+1)
    inspect(config)
    dependencies = {str(BASE):digest(base), str(ENGINE):digest(read(ENGINE, 128*1024*1024))}
    rule_files = config.get("rule-files", [])
    if type(rule_files) is not list or len(rule_files) > 64:
        raise Fault("CONFIG_UNSUPPORTED")
    directory = config.get("default-rule-path")
    if rule_files and (type(directory) is not str or not Path(directory).is_absolute()):
        raise Fault("CONFIG_UNSUPPORTED")
    seen = set(); total = 0
    for name in rule_files:
        if type(name) is not str or not name or re.search(r"[*?\[\]$\x00-\x20]", name):
            raise Fault("CONFIG_UNSUPPORTED")
        path = Path(name) if Path(name).is_absolute() else Path(directory) / name
        content = read(path)
        total += len(content)
        if total > FILE_LIMIT:
            raise Fault("LIMIT")
        identifiers = rules(content)
        if seen & identifiers:
            raise Fault("RULE_CONFLICT")
        seen |= identifiers
        dependencies[str(path)] = digest(content)
    for key in ("classification-file", "reference-config-file", "threshold-file",
                "reputation-categories-file"):
        value = config.get(key)
        if value:
            if type(value) is not str or not Path(value).is_absolute():
                raise Fault("CONFIG_UNSUPPORTED")
            dependencies[value] = digest(read(value, 4*1024*1024))
    if config.get("reputation-files"):
        raise Fault("CONFIG_UNSUPPORTED")
    return config, dependencies, seen

def overlay(interface, home_net, variables):
    # Only one controlled metadata output; Suricata's merged effective config
    # is checked separately before any native test or activation.
    if type(variables) is not dict or type(variables.get("address-groups",{})) is not dict:
        raise Fault("CONFIG_UNSUPPORTED")
    variables = json.loads(json.dumps(variables))
    variables.setdefault("address-groups",{})["HOME_NET"] = "["+home_net+"]"
    return ("%YAML 1.1\n---\nvars: " + json.dumps(variables,sort_keys=True) + "\n"
        "outputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n"
        "      filename: eve.json\n      threaded: false\n      types:\n"
        "        - alert:\n            payload: no\n            payload-printable: no\n"
        "            packet: no\n            metadata: no\n            tagged-packets: no\n"
        "        - flow\n        - stats:\n            totals: yes\n            threads: no\n"
        "stats:\n  enabled: yes\n  interval: 30\nunix-command:\n  enabled: no\n"
        "af-packet:\n  - interface: " + interface + "\n    threads: 1\n"
        "    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n").encode()

def command(generation, interface, test=False):
    directory = GENS / generation
    result = [str(ENGINE), "-c", str(BASE), "--include", str(directory / "overlay.yaml"),
              "-s", str(directory / "suricata.rules"), "--af-packet=" + interface,
              "--runmode", "single", "--init-errors-fatal", "-l", str(directory / "test" if test else LOG)]
    return result

def dropin(generation, interface):
    argv = command(generation, interface) + ["--pidfile", "/run/suricata/suricata.pid",
                                           "--user", "suricata", "--group", "suricata"]
    return ("# MEGALODON passive additive rules v1\n[Service]\nType=simple\nGroup=suricata\n"
            "RuntimeDirectory=suricata\nRuntimeDirectoryMode=0770\nPIDFile=/run/suricata/suricata.pid\n"
            "ExecStart=\nExecStart=" + " ".join(argv) + "\nExecStop=\n"
            "TimeoutStartSec=45\nTimeoutStopSec=15\nKillMode=control-group\n").encode()

def effective(generation, interface):
    output, code = run(command(generation, interface, True) + ["--dump-config"], 20)
    if code:
        raise Fault("TEST_FAILED")
    values = {}
    try:
        for line in output.decode().splitlines():
            if not line.strip():
                continue
            key, separator, value = line.partition(" = ")
            if not separator or key in values:
                raise Fault("CONFIG_UNSUPPORTED")
            values[key] = value
    except UnicodeError:
        raise Fault("CONFIG_UNSUPPORTED") from None
    # Verify merged lists, not only the YAML fragment: retained old output
    # entries, packet fields, or inline configuration must fail closed.
    expected = {
        "outputs.0":"eve-log", "outputs.0.eve-log.enabled":"yes",
        "outputs.0.eve-log.filetype":"regular", "outputs.0.eve-log.filename":"eve.json",
        "outputs.0.eve-log.threaded":"false", "outputs.0.eve-log.types.0":"alert",
        "outputs.0.eve-log.types.0.alert.payload":"no",
        "outputs.0.eve-log.types.0.alert.payload-printable":"no",
        "outputs.0.eve-log.types.0.alert.packet":"no",
        "outputs.0.eve-log.types.0.alert.metadata":"no",
        "outputs.0.eve-log.types.0.alert.tagged-packets":"no",
        "outputs.0.eve-log.types.1":"flow", "outputs.0.eve-log.types.2":"stats",
        "outputs.0.eve-log.types.2.stats.totals":"yes",
        "outputs.0.eve-log.types.2.stats.threads":"no",
    }
    observed = {key:value for key,value in values.items() if key.startswith("outputs.")}
    # Container keys have an empty value in some supported engine versions.
    observed = {key:value for key,value in observed.items() if value not in {"", "(null)"} or key in expected}
    if observed != expected or values.get("unix-command.enabled") != "no":
        raise Fault("CONFIG_UNSUPPORTED")
    capture = {key:value for key,value in values.items() if key.startswith("af-packet.") and value not in {"", "(null)"}}
    allowed = {"af-packet.0.interface":interface, "af-packet.0.threads":"1",
               "af-packet.0.cluster-id":"99", "af-packet.0.cluster-type":"cluster_flow",
               "af-packet.0.defrag":"yes", "af-packet.0":"interface"}
    if any(key not in allowed or allowed[key] != value for key,value in capture.items()) or capture.get("af-packet.0.interface") != interface:
        raise Fault("CONFIG_UNSUPPORTED")
    return digest(output)

def native_test(generation, interface):
    _, code = run(command(generation, interface, True) + ["-T"], 90, GENS/generation/"test")
    if code:
        raise Fault("TEST_FAILED")

def supported_unit(path, raw):
    # This intentionally supports a small passive service profile. Arbitrary
    # environments, preparatory scripts, mounts or credential files would add
    # dependencies that the native candidate test does not bind.
    if path==DROP:
        try:
            text=raw.decode()
            generation=re.search(re.escape(str(GENS))+r"/([a-f0-9]{32})/overlay.yaml",text).group(1)
            interface=re.search(r"--af-packet=([A-Za-z0-9_.:@-]{1,15}) ",text).group(1)
        except (UnicodeError,AttributeError):
            raise Fault("SERVICE_UNSUPPORTED") from None
        if raw!=dropin(generation,interface):
            raise Fault("SERVICE_UNSUPPORTED")
        return
    allowed={
        "PIDFile":{"/run/suricata.pid","/run/suricata/suricata.pid"},
        "ExecStartPre":{"","/bin/rm -f /run/suricata.pid"},
        "ExecReload":{"","/bin/kill -USR2 $MAINPID"},
        "ExecStop":{"","/usr/bin/suricatasc -c shutdown"},
        "Restart":{"on-failure","no"}, "ProtectSystem":{"full"}, "ProtectHome":{"true"},
        "Group":{"suricata"}, "RuntimeDirectory":{"suricata"},
        "RuntimeDirectoryMode":{"0770"}, "Type":{"simple"},
        "TimeoutStartSec":{"45"}, "TimeoutStopSec":{"15"}, "KillMode":{"control-group"},
    }
    section=None
    try:
        for line in raw.decode().splitlines():
            line=line.strip()
            if not line or line.startswith(("#",";")):
                continue
            if line in {"[Unit]","[Service]","[Install]"}:
                section=line; continue
            key,separator,value=line.partition("=")
            key=key.strip(); value=value.strip()
            if not separator or line.endswith("\\"):
                raise Fault("SERVICE_UNSUPPORTED")
            if section=="[Unit]":
                if key in {"Description","Documentation"}:
                    continue
                if key=="After" and value=="network.target network-online.target":
                    continue
                if key=="Requires" and value=="network-online.target":
                    continue
            elif section=="[Install]" and key=="WantedBy" and value=="multi-user.target":
                continue
            elif section=="[Service]":
                if key=="ExecStart":
                    original=str(ENGINE)+" --af-packet -c "+str(BASE)+" --pidfile /run/suricata.pid --user suricata --group suricata"
                    passive=re.fullmatch(re.escape(str(ENGINE))+r" --af-packet=([A-Za-z0-9_.:@-]{1,15}) --runmode single -c "+re.escape(str(BASE))+r" --pidfile /run/suricata/suricata.pid --user suricata --group suricata",value)
                    if value in {"",original} or passive:
                        continue
                elif key in allowed and value in allowed[key]:
                    continue
            raise Fault("SERVICE_UNSUPPORTED")
    except UnicodeError:
        raise Fault("SERVICE_UNSUPPORTED") from None

def service_identity():
    output, code = run([str(SYSTEMCTL), "show", "suricata.service", "--property=FragmentPath",
                        "--property=DropInPaths", "--property=NeedDaemonReload"])
    if code:
        raise Fault("SERVICE_UNSUPPORTED")
    try:
        fields = dict(line.split("=", 1) for line in output.decode().splitlines())
        fragment = Path(fields["FragmentPath"])
        overrides = fields.get("DropInPaths", "").split()
    except (ValueError, KeyError, UnicodeError):
        raise Fault("SERVICE_UNSUPPORTED") from None
    if fields.get("NeedDaemonReload") != "no" or str(fragment) not in {
            str(UNIT), str(LOCAL_UNIT)}:
        raise Fault("SERVICE_UNSUPPORTED")
    allowed = {str(DROP_DIR/"zz-megalodon-passive.conf"), str(DROP)}
    if len(overrides) > 2 or any(path not in allowed for path in overrides):
        raise Fault("SERVICE_UNSUPPORTED")
    if DROP_DIR.exists():
        safe(DROP_DIR, True)
        disk = {str(path) for path in DROP_DIR.iterdir() if path.name.endswith(".conf")}
        if disk != set(overrides):
            raise Fault("SERVICE_UNSUPPORTED")
    result = {}
    for path in [fragment, *map(Path, overrides)]:
        raw = read(path, 65536)
        supported_unit(path,raw)
        result[str(path)] = digest(raw)
    return result

def preserved_service(identity):
    if type(identity) is not dict or any(type(path) is not str or type(sha) is not str for path,sha in identity.items()):
        raise Fault("STALE_GENERATION")
    return {path:sha for path,sha in identity.items() if path!=str(DROP)}

def disk_service(expected):
    """Check preserved files even during recovery before daemon-reload works."""
    expected=preserved_service(expected)
    fragment=LOCAL_UNIT if LOCAL_UNIT.exists() else UNIT
    paths={str(fragment)}
    if DROP_DIR.exists():
        safe(DROP_DIR,True)
        paths|={str(path) for path in DROP_DIR.iterdir() if path.name.endswith(".conf") and path!=DROP}
    if paths!=set(expected) or any(digest(read(path,65536))!=expected[path] for path in paths):
        raise Fault("STALE_GENERATION")

def active():
    _, code = run([str(SYSTEMCTL), "is-active", "--quiet", "suricata.service"], 10)
    if code not in (0, 3):
        raise Fault("SERVICE_UNSUPPORTED")
    return code == 0

def restart(was_active=True):
    _, code = run([str(SYSTEMCTL), "daemon-reload"], 20)
    if code:
        raise Fault("RESTART_FAILED")
    _, code = run([str(SYSTEMCTL), "restart" if was_active else "stop", "suricata.service"], 65)
    if code or active() != was_active:
        raise Fault("RESTART_FAILED")

def state():
    path = ROOT/"state.json"
    value = load(path) if path.exists() else {"active":None, "rollback":None}
    if type(value) is not dict or set(value) != {"active", "rollback"}:
        raise Fault("STALE_GENERATION")
    if value["active"] is not None:
        token(value["active"])
    return value

def token(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise Fault("STALE_GENERATION")
    return value

def scope(interface, home_net):
    if type(interface) is not str or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", interface):
        raise Fault("CONFIG_UNSUPPORTED")
    if interface not in {name for _, name in socket.if_nameindex()}:
        raise Fault("CONFIG_UNSUPPORTED")
    try:
        if type(home_net) is not str or len(home_net) > 49 or "/" not in home_net or str(ipaddress.ip_network(home_net, strict=True)) != home_net:
            raise Fault("CONFIG_UNSUPPORTED")
    except ValueError:
        raise Fault("CONFIG_UNSUPPORTED") from None

def receipt(action, status, manifest=None, runtime="not_checked", rollback="none", error=None):
    manifest = manifest or {}
    return dict(schema=SCHEMA, action=action, state=status, checked_at=stamp(),
        generation=manifest.get("generation"), interface=manifest.get("interface"),
        home_net=manifest.get("home_net"), rule_count=manifest.get("rule_count",0),
        native_test_passed=bool(manifest), runtime_state=runtime, rollback=rollback, error=error)

def stage(interface, home_net):
    scope(interface, home_net)
    if (ROOT/"pending.json").exists():
        raise Fault("PENDING_RECOVERY")
    config, dependencies, existing = source_inputs()
    service = service_identity()
    if len(list(GENS.iterdir())) >= 16:
        raise Fault("LIMIT")
    generation = uuid.uuid4().hex
    directory = GENS/generation
    mkdir(directory)
    for name in ("data", "output", "empty", "test"):
        mkdir(directory/name)
    write(directory/"empty.conf", b"")
    updater_config = {
        "suricata":str(ENGINE), "suricata-conf":str(BASE), "sources":[SOURCE],
        "local":[], "dist-rule-directory":str(directory/"empty"),
        **{key:str(directory/"empty.conf") for key in ("enable-conf","disable-conf","drop-conf","modify-conf")},
    }
    # JSON is a strict YAML subset accepted by suricata-update.
    write(directory/"update.yaml", json.dumps(updater_config).encode())
    safe(UPDATER)
    _, code = run([str(UPDATER), "-D",str(directory/"data"), "-o",str(directory/"output"),
                   "-c",str(directory/"update.yaml"), "--no-reload", "--no-test", "--fail"], 180, directory)
    if code:
        raise Fault("UPDATE_FAILED")
    candidate = read(directory/"output"/"suricata.rules")
    identities = rules(candidate)
    if not identities:
        raise Fault("RULE_UNSUPPORTED")
    if identities & existing:
        raise Fault("RULE_CONFLICT")
    write(directory/"suricata.rules", candidate, 0o640)
    write(directory/"overlay.yaml", overlay(interface,home_net,config.get("vars",{})), 0o640)
    effective_hash = effective(generation,interface)
    native_test(generation,interface)
    if source_inputs()[1] != dependencies or service_identity() != service:
        raise Fault("STALE_GENERATION")
    manifest = dict(generation=generation, interface=interface, home_net=home_net,
        rule_count=len(identities), source=SOURCE, staged_at=stamp(), dependencies=dependencies,
        service=service, effective_sha256=effective_hash,
        rules_sha256=digest(candidate), overlay_sha256=digest(read(directory/"overlay.yaml")))
    save(directory/"manifest.json",manifest)
    group = grp.getgrnam("suricata").gr_gid
    for path in (directory, directory/"suricata.rules", directory/"overlay.yaml"):
        os.chown(path, TRUSTED_UID, group)
    directory.chmod(0o750)
    return receipt("stage","staged",manifest)

def verify(generation, compare_service=True, recovering=False):
    token(generation)
    directory = GENS/generation
    manifest = load(directory/"manifest.json")
    keys={"generation","interface","home_net","rule_count","source","staged_at","dependencies",
          "service","effective_sha256","rules_sha256","overlay_sha256"}
    if type(manifest) is not dict or set(manifest)!=keys or manifest["generation"]!=generation or manifest["source"]!=SOURCE:
        raise Fault("STALE_GENERATION")
    scope(manifest["interface"],manifest["home_net"])
    config, dependencies, existing = source_inputs()
    candidate = read(directory/"suricata.rules")
    identifiers = rules(candidate)
    if (dependencies != manifest["dependencies"] or digest(candidate) != manifest["rules_sha256"]
            or digest(read(directory/"overlay.yaml")) != manifest["overlay_sha256"]
            or read(directory/"overlay.yaml") != overlay(manifest["interface"],manifest["home_net"],config.get("vars",{}))
            or type(manifest["rule_count"]) is not int or len(identifiers) != manifest["rule_count"]
            or not identifiers or identifiers & existing):
        raise Fault("STALE_GENERATION")
    disk_service(manifest["service"])
    if not recovering:
        service=service_identity()
        if ((compare_service and service!=manifest["service"]) or
                preserved_service(service)!=preserved_service(manifest["service"])):
            raise Fault("STALE_GENERATION")
    if effective(generation,manifest["interface"]) != manifest["effective_sha256"]:
        raise Fault("STALE_GENERATION")
    native_test(generation,manifest["interface"])
    unchanged(manifest)
    return manifest

def unchanged(manifest):
    directory=GENS/token(manifest["generation"])
    if (source_inputs()[1]!=manifest["dependencies"] or
            digest(read(directory/"suricata.rules"))!=manifest["rules_sha256"] or
            digest(read(directory/"overlay.yaml"))!=manifest["overlay_sha256"]):
        raise Fault("STALE_GENERATION")
    disk_service(manifest["service"])

def restore(previous):
    if type(previous) is not dict or set(previous)!={"generation","dropin","was_active","dependencies","service"} or type(previous["was_active"]) is not bool:
        raise Fault("STALE_GENERATION")
    if source_inputs()[1]!=previous["dependencies"]:
        raise Fault("STALE_GENERATION")
    disk_service(previous["service"])
    if previous["generation"] is not None:
        token(previous["generation"])
    raw = previous["dropin"]
    if raw is None:
        if previous["generation"] is not None:
            raise Fault("STALE_GENERATION")
        testdir=ROOT/"recovery-test"
        mkdir(testdir)
        _,code=run([str(ENGINE),"-T","-c",str(BASE),"--init-errors-fatal","-l",str(testdir)],90,testdir)
        if code:
            raise Fault("TEST_FAILED")
        if DROP.exists():
            safe(DROP); DROP.unlink()
    else:
        if type(raw) is not str or len(raw)>32768:
            raise Fault("STALE_GENERATION")
        try:
            decoded=base64.b64decode(raw,validate=True)
        except ValueError:
            raise Fault("STALE_GENERATION") from None
        if previous["generation"] is None:
            raise Fault("STALE_GENERATION")
        manifest = verify(previous["generation"],False,recovering=True)
        if decoded != dropin(previous["generation"],manifest["interface"]):
            raise Fault("STALE_GENERATION")
        write(DROP,decoded,0o644)
    restart(previous["was_active"])

def known_drop(pending):
    """Do not overwrite an operator edit even after interrupted activation."""
    if type(pending) is not dict or set(pending)!={"generation","previous"}:
        raise Fault("STALE_GENERATION")
    generation=token(pending["generation"])
    manifest=load(GENS/generation/"manifest.json")
    if type(manifest) is not dict:
        raise Fault("STALE_GENERATION")
    scope(manifest.get("interface"),manifest.get("home_net"))
    candidate=dropin(generation,manifest["interface"])
    previous=pending["previous"]
    if type(previous) is not dict or "dropin" not in previous:
        raise Fault("STALE_GENERATION")
    try:
        old=base64.b64decode(previous["dropin"],validate=True) if previous["dropin"] is not None else None
    except (ValueError,TypeError):
        raise Fault("STALE_GENERATION") from None
    actual=read(DROP,16384) if DROP.exists() or DROP.is_symlink() else None
    if actual not in (candidate,old):
        raise Fault("STALE_GENERATION")

def activate(generation):
    if (ROOT/"pending.json").exists():
        raise Fault("PENDING_RECOVERY")
    manifest = verify(generation)
    old = state()
    if old["active"] == generation:
        raise Fault("STALE_GENERATION")
    if DROP.exists():
        if old["active"] is None:
            raise Fault("SERVICE_UNSUPPORTED")
        old_manifest = verify(old["active"],False)
        previous_raw=read(DROP,16384)
        if previous_raw != dropin(old["active"],old_manifest["interface"]):
            raise Fault("STALE_GENERATION")
    else:
        if old["active"] is not None:
            raise Fault("STALE_GENERATION")
        previous_raw=None
    unchanged(manifest)
    if service_identity()!=manifest["service"]:
        raise Fault("STALE_GENERATION")
    mkdir(DROP_DIR,0o755)
    safe(LOG,True)
    if (LOG/"eve.json").is_symlink():
        raise Fault("UNSAFE_PATH")
    previous=dict(generation=old["active"],dropin=base64.b64encode(previous_raw).decode() if previous_raw else None,
                  was_active=active(),dependencies=manifest["dependencies"],service=manifest["service"])
    pending=dict(generation=generation,previous=previous)
    save(ROOT/"pending.json",pending)
    try:
        write(DROP,dropin(generation,manifest["interface"]),0o644)
        restart(True)
        if read(DROP) != dropin(generation,manifest["interface"]):
            raise Fault("STALE_GENERATION")
        save(ROOT/"state.json",dict(active=generation,rollback=previous))
        (ROOT/"pending.json").unlink()
    except (Fault,OSError):
        try:
            known_drop(pending)
            restore(previous)
            save(ROOT/"state.json",old)
            (ROOT/"pending.json").unlink()
        except (Fault,OSError):
            return receipt("activate","needs_review",manifest,"unknown","failed","ROLLBACK_FAILED")
        return receipt("activate","failed",manifest,"active_at_check" if previous["was_active"] else "inactive_at_check","restored","RESTART_FAILED")
    return receipt("activate","active",manifest,"active_at_check","available")

def rollback():
    current=state()
    if (ROOT/"pending.json").exists():
        pending=load(ROOT/"pending.json")
        if type(pending) is not dict or set(pending)!={"generation","previous"}:
            raise Fault("STALE_GENERATION")
        token(pending["generation"])
        previous=pending["previous"]
    else:
        previous=current["rollback"]
        if previous is None:
            raise Fault("NO_ROLLBACK")
        # Refuse to overwrite an operator-edited current override.
        active_manifest=load(GENS/token(current["active"])/"manifest.json")
        scope(active_manifest.get("interface"),active_manifest.get("home_net"))
        if read(DROP)!=dropin(current["active"],active_manifest["interface"]):
            raise Fault("STALE_GENERATION")
        save(ROOT/"pending.json",dict(generation=current["active"],previous=previous))
    try:
        known_drop(load(ROOT/"pending.json"))
        restore(previous)
        save(ROOT/"state.json",dict(active=previous["generation"],rollback=None))
        (ROOT/"pending.json").unlink()
    except (Fault,OSError):
        return receipt("rollback","needs_review",runtime="unknown",rollback="failed",error="ROLLBACK_FAILED")
    manifest=load(GENS/previous["generation"]/"manifest.json") if previous["generation"] else None
    return receipt("rollback","rolled_back",manifest,"active_at_check" if previous["was_active"] else "inactive_at_check","restored")

def check():
    if (ROOT/"pending.json").exists():
        raise Fault("PENDING_RECOVERY")
    current=state()
    if current["active"] is None:
        return receipt("check","unconfigured")
    manifest=verify(current["active"],False)
    service_identity()
    if read(DROP)!=dropin(current["active"],manifest["interface"]):
        raise Fault("STALE_GENERATION")
    running=active()
    return receipt("check","active" if running else "needs_review",manifest,
                   "active_at_check" if running else "inactive_at_check",
                   "available" if current["rollback"] else "none")

def main():
    action=sys.argv[1] if len(sys.argv)>1 else "check"
    try:
        if os.geteuid()!=0 or not os.environ.get("PKEXEC_UID","").isdigit() or int(os.environ["PKEXEC_UID"])<=0:
            raise Fault("AUTH_REQUIRED")
        if action not in {"stage","activate","rollback","check"} or len(sys.argv)!={"stage":4,"activate":3,"rollback":2,"check":2}.get(action):
            raise Fault("CONFIG_UNSUPPORTED")
        safe(ENGINE); safe(SYSTEMCTL)
        mkdir(ROOT,0o750)
        group=grp.getgrnam("suricata").gr_gid
        os.chown(ROOT,0,group)
        mkdir(GENS,0o750); os.chown(GENS,0,group)
        lock=ROOT/"operation.lock"
        try:
            created=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            pass
        else:
            os.close(created)
        safe(lock)
        fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise Fault("BUSY") from None
            result=stage(*sys.argv[2:]) if action=="stage" else activate(sys.argv[2]) if action=="activate" else rollback() if action=="rollback" else check()
        finally:
            os.close(fd)
    except Fault as error:
        recoverable=(ROOT/"pending.json").exists()
        if not recoverable:
            try:
                recoverable=bool(state()["rollback"])
            except (Fault,OSError,ValueError):
                pass
        result=receipt(action,"needs_review" if str(error) in {"PENDING_RECOVERY","STALE_GENERATION"} else "failed",
                       rollback="available" if recoverable else "none",error=str(error))
    except (OSError,ValueError,KeyError):
        result=receipt(action,"failed",error="HELPER_FAILED")
    print(json.dumps(result,separators=(",",":"),allow_nan=False))
    return 1 if result["error"] else 0

if __name__=="__main__":
    sys.exit(main())
'''


class SuricataRules:
    """Synchronous explicit actions, intended for the existing support worker."""

    def __init__(self, *, run=_run_fixed):
        execution_boundary.require_effects_allowed()
        self.run = run
        self._lock = Lock()
        self._busy = Lock()
        self._status = dict(schema=SCHEMA, action=None, state="unconfigured", checked_at=None,
                            generation=None, interface=None, home_net=None, rule_count=0,
                            native_test_passed=False, runtime_state="not_checked", rollback="none",
                            error=None, message="Rules lifecycle has not been checked in this session.")

    def snapshot(self):
        with self._lock:
            return deepcopy(self._status)

    def stage(self, interface, home_net):
        execution_boundary.require_effects_allowed()
        return self._execute("stage", *validate_scope(interface, home_net))

    def activate(self, generation):
        execution_boundary.require_effects_allowed()
        return self._execute("activate", _generation(generation))

    def rollback(self):
        execution_boundary.require_effects_allowed()
        return self._execute("rollback")

    def check(self):
        """Explicit verification action; never call this from a GET/snapshot."""
        execution_boundary.require_effects_allowed()
        return self._execute("check")

    def _execute(self, action, *arguments):
        execution_boundary.require_effects_allowed()
        if not self._busy.acquire(blocking=False):
            raise ValueError(MESSAGES["BUSY"])
        try:
            argv = ["/usr/bin/pkexec", "/usr/bin/python3", "-I", "-c", ROOT_PROGRAM, action, *arguments]
            try:
                output, code = self.run(argv, MAX_RECEIPT, 420)
                value = _receipt(output, action)
                if (code == 0) != (value["error"] is None):
                    raise ValueError("Invalid helper result.")
            except Exception:
                value = dict(schema=SCHEMA, action=action, state="needs_review",
                             checked_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                             generation=None, interface=None, home_net=None, rule_count=0,
                             native_test_passed=False, runtime_state="unknown", rollback="none",
                             error="HELPER_FAILED")
            messages = {
                "staged":"Candidate passed a dated native test; activation has not been requested.",
                "active":"Managed configuration passed a dated check; capture coverage is not established.",
                "rolled_back":"Previous service configuration was restored at the recorded time.",
                "unconfigured":"No active managed rules generation was recorded.",
                "needs_review":"The managed service was not active at the recorded check; review it.",
            }
            value["message"] = MESSAGES.get(value["error"], messages.get(value["state"], "Review the rules operation."))
            with self._lock:
                self._status = value
            if value["error"]:
                raise ValueError(value["message"])
            return self.snapshot()
        finally:
            self._busy.release()


def _receipt(output, action):
    if type(output) not in (bytes, str) or len(output) > MAX_RECEIPT:
        raise ValueError("Invalid rules receipt.")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate receipt field.")
            result[key] = value
        return result
    value = json.loads(output, object_pairs_hook=unique)
    fields = {"schema","action","state","checked_at","generation","interface","home_net",
              "rule_count","native_test_passed","runtime_state","rollback","error"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != SCHEMA
            or value["action"] != action or value["state"] not in
                {"unconfigured","staged","active","rolled_back","failed","needs_review"}
            or value["runtime_state"] not in {"active_at_check","inactive_at_check","not_checked","unknown"}
            or value["rollback"] not in {"available","restored","failed","none"}
            or type(value["native_test_passed"]) is not bool
            or type(value["rule_count"]) is not int or not 0 <= value["rule_count"] <= 200000
            or (value["error"] is not None and value["error"] not in MESSAGES)):
        raise ValueError("Invalid rules receipt.")
    if type(value["checked_at"]) is not str or not value["checked_at"].endswith("Z"):
        raise ValueError("Invalid receipt time.")
    datetime.fromisoformat(value["checked_at"].replace("Z", "+00:00"))
    if value["generation"] is not None:
        _generation(value["generation"])
        _interface(value["interface"])
        valid_home_net(value["home_net"])
    elif value["interface"] is not None or value["home_net"] is not None or value["rule_count"] or value["native_test_passed"]:
        raise ValueError("Incomplete generation receipt.")
    if value["state"] in {"staged","active"} and (not value["generation"] or not value["native_test_passed"] or value["error"]):
        raise ValueError("Unverified generation receipt.")
    return value
