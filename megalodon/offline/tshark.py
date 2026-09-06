"""Fixed-profile offline TShark adapter; never a general command runner."""

from __future__ import annotations

import errno
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time

from ..models import PacketEvent
from .common import (Batch, Limits, OfflineError, ip, open_input,
                     require_unprivileged_linux, timestamp, uint, version)

EXECUTABLE = '/usr/bin/tshark'
ADAPTER = 'tshark-fields-v1'
FIELDS = ('frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
          'ip.proto', 'ipv6.nxt', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
          'udp.dstport', 'tcp.flags', 'frame.len')
MAGIC = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
         b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'}
FLAG_NAMES = ('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR')


def fixed_argv(fd: int, limits: Limits) -> tuple[str, ...]:
    uint(fd, 2**31 - 1)
    args = [EXECUTABLE, '-n', '-l', '-r', f'/proc/self/fd/{fd}',
            '-c', str(limits.records + 1), '-T', 'fields',
            '-E', 'header=n', '-E', 'separator=/t', '-E', 'quote=n',
            '-E', 'occurrence=a', '-E', 'aggregator=,']
    for field in FIELDS:
        args.extend(('-e', field))
    return tuple(args)


def _bounded_process(argv: tuple[str, ...], *, env: dict[str, str], cwd: str,
                     limits: Limits, pass_fds: tuple[int, ...] = ()) -> bytes:
    """Drain both pipes while enforcing caps; discard stderr, kill/reap on every exit."""
    output = bytearray()
    stderr_size = 0
    process = None
    deadline = time.monotonic() + limits.timeout_seconds
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=env, cwd=cwd,
                                   close_fds=True, pass_fds=pass_fds, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OfflineError('TIMEOUT')
                for key, _ in selector.select(min(remaining, 0.1)):
                    is_stdout = key.fileobj is process.stdout
                    used = len(output) if is_stdout else stderr_size
                    cap = limits.stdout_bytes if is_stdout else limits.stderr_bytes
                    chunk = os.read(key.fd, min(4096, cap - used + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if used + len(chunk) > cap:
                        raise OfflineError('STDOUT_LIMIT' if is_stdout else 'STDERR_LIMIT')
                    if is_stdout:
                        output.extend(chunk)
                    else:
                        stderr_size += len(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OfflineError('TIMEOUT')
            if process.wait(timeout=remaining) != 0:
                raise OfflineError('ANALYZER_FAILED')
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise OfflineError('TIMEOUT') from None
    except OSError:
        raise OfflineError('ANALYZER_IO_ERROR') from None
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def parse_fields(row: str) -> PacketEvent | None:
    """Reject multi-valued/tunnel ambiguity, never silently take the first field."""
    if len(row) > 1024 or any(ord(c) < 32 and c != '\t' or ord(c) > 126 for c in row):
        raise OfflineError('INVALID_FIELD_ROW')
    columns = row.split('\t')
    if len(columns) != len(FIELDS) or any(',' in value for value in columns):
        raise OfflineError('AMBIGUOUS_FIELD_ROW')
    at, src4, dst4, src6, dst6, proto4, proto6, ts, td, us, ud, flags, size = columns
    observed = timestamp(at)
    length = uint(size, 262144)
    if not any((src4, dst4, src6, dst6, proto4, proto6)):
        if any((ts, td, us, ud, flags)):
            raise OfflineError('INVALID_FIELD_ROW')
        return None  # Explicitly counted non-IP frame, not a fabricated event.
    if bool(src4 or dst4 or proto4) == bool(src6 or dst6 or proto6):
        raise OfflineError('AMBIGUOUS_FIELD_ROW')
    src, dst, proto = (src4, dst4, proto4) if src4 else (src6, dst6, proto6)
    src, dst = ip(src), ip(dst)
    number = uint(proto, 255)
    if (':' in src) != bool(src6) or (':' in dst) != bool(src6):
        raise OfflineError('INVALID_FIELD_ROW')
    source_port = destination_port = None
    tcp_flags = frozenset()
    if number in {6, 17}:
        a, b = (ts, td) if number == 6 else (us, ud)
        if (number == 6 and (us or ud)) or (number == 17 and (ts or td or flags)):
            raise OfflineError('AMBIGUOUS_FIELD_ROW')
        if not a and not b and not flags:
            return None  # Fragment/unsupported transport; not counted as a full packet event.
        source_port, destination_port = uint(a, 65535), uint(b, 65535)
        if number == 6:
            if not re.fullmatch(r'0x[0-9a-fA-F]{1,4}', flags):
                raise OfflineError('INVALID_TCP_FLAGS')
            bits = uint(int(flags, 16), 255)
            tcp_flags = frozenset(name for bit, name in enumerate(FLAG_NAMES) if bits & (1 << bit))
    elif any((ts, td, us, ud, flags)):
        raise OfflineError('UNSUPPORTED_TRANSPORT')
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPV6'}.get(number, 'OTHER')
    return PacketEvent(observed, src, dst, protocol, source_port, destination_port,
                       tcp_flags=tcp_flags, byte_count=length,
                       metadata={'source_adapter': ADAPTER})


def replay(root: str, relative: str, limits: Limits = Limits()) -> Batch:
    require_unprivileged_linux()
    if not relative.endswith(('.pcap', '.pcapng')):
        raise OfflineError('UNSUPPORTED_CAPTURE_FORMAT')
    try:
        info = os.lstat(EXECUTABLE)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise OfflineError('UNTRUSTED_ANALYZER')
    except OSError:
        raise OfflineError('TSHARK_UNAVAILABLE') from None
    try:
        if os.getxattr(EXECUTABLE, 'security.capability'):
            raise OfflineError('UNTRUSTED_ANALYZER')
    except OSError as exc:
        if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
            raise OfflineError('UNTRUSTED_ANALYZER') from None
    with open_input(root, relative, limits) as (fd, size), tempfile.TemporaryDirectory() as home:
        magic = os.pread(fd, 4, 0)
        if magic not in MAGIC or size < (28 if magic == b'\x0a\x0d\x0d\x0a' else 24):
            raise OfflineError('UNSUPPORTED_CAPTURE_FORMAT')
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': home,
               'XDG_CONFIG_HOME': home, 'XDG_CACHE_HOME': home, 'WIRESHARK_CONFIG_DIR': home}
        probe_limits = Limits(stdout_bytes=8192, stderr_bytes=4096, timeout_seconds=5)
        probe = _bounded_process((EXECUTABLE, '--version'), env=env, cwd=home, limits=probe_limits)
        match = re.match(rb'TShark \(Wireshark\) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\s|\()', probe)
        if not match:
            raise OfflineError('UNRECOGNIZED_ANALYZER_VERSION')
        tool_version = version(match.group(1).decode('ascii'))
        raw = _bounded_process(fixed_argv(fd, limits), env=env, cwd=home,
                               limits=limits, pass_fds=(fd,))
        if raw and not raw.endswith(b'\n'):
            raise OfflineError('TRUNCATED_ANALYZER_OUTPUT')
        if raw.count(b'\n') > limits.records:
            raise OfflineError('RECORD_LIMIT')
        rows = raw.split(b'\n')[:-1] if raw else []
        records = []
        for row in rows:
            if len(row) > min(1024, limits.line_bytes):
                raise OfflineError('FIELD_LINE_LIMIT')
            try:
                event = parse_fields(row.decode('ascii'))
            except UnicodeDecodeError:
                raise OfflineError('INVALID_ENCODING') from None
            if event is not None:
                records.append(event)
        result = Batch(ADAPTER, 'packet', tuple(records), len(rows), len(rows) - len(records),
                       size, tool_version, 'subprocess_version')
    return result  # Only after successful exit, full parse, and input stability check.
