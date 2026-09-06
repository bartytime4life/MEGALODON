"""Bounded contracts and descriptor-relative Linux file access."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import os
import re
import stat
import sys
import time
from typing import Iterator

from ..models import PacketEvent
from ..validation import parse_ip, ValidationError

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_EPOCH = 4102444800  # 2100-01-01, exclusive; never substitute the current time.
STATES = frozenset({'S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR',
                    'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH'})


class OfflineError(ValueError):
    """A fixed diagnostic code; never include file names or analyzer output."""


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 64 * 1024 * 1024
    records: int = 10_000
    stdout_bytes: int = 8 * 1024 * 1024
    stderr_bytes: int = 32 * 1024
    line_bytes: int = 16 * 1024
    report_bytes: int = 16 * 1024 * 1024
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        ceilings = (64 * 1024 * 1024, 10_000, 8 * 1024 * 1024, 32 * 1024,
                    16 * 1024, 16 * 1024 * 1024, 30)
        for name, ceiling in zip(self.__dataclass_fields__, ceilings):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise OfflineError('INVALID_LIMIT')


def require_unprivileged_linux() -> None:
    if not sys.platform.startswith('linux'):
        raise OfflineError('LINUX_REQUIRED')
    if os.getuid() == 0 or os.geteuid() == 0:
        raise OfflineError('NON_ROOT_REQUIRED')
    try:
        with open('/proc/self/status', 'rt', encoding='ascii') as status:
            text = status.read(65537)
        names = {'CapInh', 'CapPrm', 'CapEff', 'CapAmb'}
        values = dict(line.split(':', 1) for line in text.splitlines()
                      if line.split(':', 1)[0] in names)
        if len(text) > 65536 or set(values) != names or any(int(v.strip(), 16) for v in values.values()):
            raise OfflineError('CAPABILITY_FREE_PROCESS_REQUIRED')
    except (OSError, ValueError):
        raise OfflineError('CAPABILITY_FREE_PROCESS_REQUIRED') from None


def uint(value: object, maximum: int) -> int:
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,20}', value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= maximum:
        raise OfflineError('INVALID_INTEGER')
    return value


def seconds_us(value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise OfflineError('INVALID_TIME')
    text = str(value)
    if not re.fullmatch(r'[0-9]{1,10}(?:\.[0-9]{1,24})?(?:[eE][+-]?[0-9]{1,2})?', text):
        raise OfflineError('INVALID_TIME')
    try:
        number = Decimal(text)
        if not number.is_finite() or not 0 <= number < maximum:
            raise OfflineError('INVALID_TIME')
        return int(number * 1_000_000)  # Truncate sub-microsecond precision.
    except InvalidOperation:
        raise OfflineError('INVALID_TIME') from None


def timestamp(value: object) -> datetime:
    return EPOCH + timedelta(microseconds=seconds_us(value, MAX_EPOCH))


def ip(value: object) -> str:
    if not isinstance(value, str) or len(value) > 45 or value != value.strip():
        raise OfflineError('INVALID_ADDRESS')
    try:
        return parse_ip(value)
    except ValidationError:
        raise OfflineError('INVALID_ADDRESS') from None


def version(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', value):
        raise OfflineError('INVALID_TOOL_VERSION')
    return value


@dataclass(frozen=True)
class FlowRecord:
    """One Zeek connection, NOT one packet or a reconstructed packet stream."""
    observed_at: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    duration_us: int | None
    orig_packets: int
    resp_packets: int
    byte_count: int
    conn_state: str

    def __post_init__(self) -> None:
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo != timezone.utc:
            raise OfflineError('INVALID_TIME')
        if not EPOCH <= self.observed_at < EPOCH + timedelta(seconds=MAX_EPOCH):
            raise OfflineError('INVALID_TIME')
        object.__setattr__(self, 'src_ip', ip(self.src_ip))
        object.__setattr__(self, 'dst_ip', ip(self.dst_ip))
        if (':' in self.src_ip) != (':' in self.dst_ip):
            raise OfflineError('ADDRESS_FAMILY_MISMATCH')
        if self.protocol not in {'TCP', 'UDP', 'ICMP'} or self.conn_state not in STATES:
            raise OfflineError('INVALID_FLOW')
        uint(self.src_port, 65535)
        uint(self.dst_port, 65535)
        uint(self.orig_packets, 2**31 - 1)
        uint(self.resp_packets, 2**31 - 1)
        uint(self.byte_count, 2**41 - 2)
        if self.duration_us is not None:
            uint(self.duration_us, 604800 * 1_000_000 - 1)


Record = PacketEvent | FlowRecord


@dataclass(frozen=True)
class Batch:
    adapter: str
    kind: str
    records: tuple[Record, ...]
    scanned: int
    skipped: int
    input_bytes: int
    tool_version: str
    version_basis: str


def _parts(value: str, *, absolute: bool) -> list[str]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise OfflineError('INVALID_PATH')
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or '://' in value:
        raise OfflineError('INVALID_PATH')
    if value.startswith('/') != absolute:
        raise OfflineError('INVALID_PATH')
    parts = value.split('/')[1:] if absolute else value.split('/')
    if absolute and value == '/':
        return []
    if any(part in {'', '.', '..'} for part in parts):
        raise OfflineError('INVALID_PATH')
    return parts


def open_directory(path: str) -> int:
    """Reject symlinks at every component; caller owns the returned descriptor."""
    parts = _parts(path, absolute=True)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def open_input(root: str, relative: str, limits: Limits) -> Iterator[tuple[int, int]]:
    """Open only a bounded regular file below a scoped, operator-chosen root."""
    parts = _parts(relative, absolute=False)
    if not _parts(root, absolute=True):
        raise OfflineError('SCOPED_INPUT_ROOT_REQUIRED')
    directory = None
    fd = None
    try:
        directory = open_directory(root)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OfflineError('REGULAR_SINGLE_LINK_FILE_REQUIRED')
        if not 0 < before.st_size <= limits.input_bytes:
            raise OfflineError('INPUT_SIZE_LIMIT')
        yield fd, before.st_size
        if _identity(os.fstat(fd)) != _identity(before):
            raise OfflineError('INPUT_CHANGED')
    except OSError:
        raise OfflineError('INPUT_IO_ERROR') from None
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


def lines(fd: int, limits: Limits) -> Iterator[str]:
    deadline = time.monotonic() + limits.timeout_seconds
    total = 0
    with os.fdopen(os.dup(fd), 'rb') as stream:
        while True:
            if time.monotonic() >= deadline:
                raise OfflineError('TIMEOUT')
            data = stream.readline(limits.line_bytes + 1)
            if not data:
                return
            total += len(data)
            if total > limits.input_bytes or len(data) > limits.line_bytes:
                raise OfflineError('INPUT_SIZE_LIMIT')
            try:
                text = data.decode('ascii')
            except UnicodeDecodeError:
                raise OfflineError('INVALID_ENCODING') from None
            yield text.removesuffix('\n')
