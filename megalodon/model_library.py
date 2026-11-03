"""Explicit, pinned GGUF staging. No provider, inference, or telemetry upload.

The catalog is repository data, never supplied by the browser or a model.
Only an explicit maintenance action opens a connection. Polling is memory-only.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import http.client
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import stat
import sys
from threading import Event, Lock
import time
from urllib.parse import urljoin, urlsplit

from . import storage

SCHEMA = "megalodon-model-library-v1"
CHUNK_BYTES = 64 * 1024
RESERVE_BYTES = 256 * 1024 * 1024
MAX_JOBS = 64
MAX_DATABASE_BYTES = 1024 * 1024
DEADLINE_SECONDS = 1800
SOCKET_TIMEOUT = 10
MAX_REDIRECTS = 3
# HTTPS file endpoints documented by Hugging Face; no Xet client/API or proxies.
DOWNLOAD_HOSTS = frozenset({
    "huggingface.co", "us.aws.cdn.hf.co", "us.gcp.cdn.hf.co",
    "cdn-lfs-us-1.hf.co", "cdn-lfs-eu-1.hf.co",
    # Legacy plain-HTTPS redirect endpoints, documented by HF staff.
    "cdn-lfs.hf.co", "cas-bridge.xethub.hf.co",
})
ERRORS = {
    "UNAVAILABLE": "The private model library is unavailable. Review its permissions and storage.",
    "BUSY": "Another model library operation is running.",
    "JOB_LIMIT": "The model library has reached its 64-job history limit.",
    "NO_SPACE": "There is not enough free space for this download and its storage reserve.",
    "NETWORK": "The model download could not complete. Check connectivity and try again explicitly.",
    "SOURCE": "The download source or response did not match the fixed download policy.",
    "SIZE": "The downloaded file did not match the pinned byte count.",
    "DIGEST": "The downloaded file did not match the pinned SHA-256.",
    "CANCELLED": "Download cancelled. Partial staging bytes were removed.",
    "DEADLINE": "The model staging time limit was reached.",
    "FILE": "A staging file is unsafe or changed. Review the private model library.",
    "INTERRUPTED": "A previous staging job was interrupted. No download was resumed.",
}


class LibraryError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in ERRORS else "UNAVAILABLE"
        super().__init__(ERRORS[self.code])


@dataclass(frozen=True)
class Artifact:
    id: str
    title: str
    repository: str
    revision: str
    filename: str
    size: int
    digest: str
    license: str

    @property
    def url(self):
        return f"https://huggingface.co/{self.repository}/resolve/{self.revision}/{self.filename}"

    def public(self):
        return dict(id=self.id, title=self.title, source="Hugging Face / " + self.repository,
                    revision=self.revision, filename=self.filename, size_bytes=self.size,
                    sha256=self.digest, license=self.license)


# Official Qwen repository, read back 2026-11-03 via the Hub blobs API.
# See docs/model-library.md for the exact upstream evidence and limits.
CATALOG = (Artifact(
    "qwen25-05b-q4km", "Qwen2.5 0.5B Instruct · Q4_K_M", "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
    "9217f5db79a29953eb74d5343926648285ec7e67", "qwen2.5-0.5b-instruct-q4_k_m.gguf",
    491400032, "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db", "Apache-2.0",
),)


def artifact(identifier):
    if type(identifier) is not str:
        raise LibraryError("SOURCE")
    for entry in CATALOG:
        if identifier == entry.id:
            return entry
    raise LibraryError("SOURCE")


def _url(value):
    if (type(value) is not str or len(value) > 8192
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise LibraryError("SOURCE")
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or parts.hostname not in DOWNLOAD_HOSTS
                or parts.port not in (None, 443) or parts.username is not None
                or parts.password is not None or parts.fragment or not parts.path.startswith("/")):
            raise LibraryError("SOURCE")
    except ValueError:
        raise LibraryError("SOURCE") from None
    return parts


def _check(stop, deadline):
    if stop.is_set():
        raise LibraryError("CANCELLED")
    if time.monotonic() >= deadline:
        raise LibraryError("DEADLINE")


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Resolve only a fixed hostname, reject non-global answers, pin one address.

    TLS still checks the original hostname. No proxy/environment/cookie/auth use.
    DNS and native filesystem calls remain cooperative-deadline limitations.
    """
    def connect(self):
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not addresses or len(addresses) > 32:
            raise LibraryError("SOURCE")
        for _, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            if not ip.is_global or ip.is_multicast or ip.is_reserved:
                raise LibraryError("SOURCE")
        family, kind, proto, _, address = addresses[0]
        raw = socket.socket(family, kind, proto)
        try:
            raw.settimeout(SOCKET_TIMEOUT)
            raw.connect(address)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


@contextmanager
def _response(entry, stop, deadline):
    url = entry.url
    for redirect in range(MAX_REDIRECTS + 1):
        _check(stop, deadline)
        parts = _url(url)
        connection = _PinnedHTTPS(parts.hostname, 443, timeout=SOCKET_TIMEOUT,
                                  context=ssl.create_default_context())
        response = None
        try:
            connection.request("GET", parts.path + ("?" + parts.query if parts.query else ""),
                               headers={"Accept-Encoding": "identity", "User-Agent": "MEGALODON-model-stage/1"})
            response = connection.getresponse()
            _check(stop, deadline)
            if response.status in (301, 302, 303, 307, 308):
                locations = response.headers.get_all("Location", [])
                if len(locations) != 1 or redirect == MAX_REDIRECTS:
                    raise LibraryError("SOURCE")
                url = urljoin(url, locations[0])
                _url(url)  # Check before another connection, including relative redirects.
                continue
            lengths = response.headers.get_all("Content-Length", [])
            if (response.status != 200 or response.headers.get_all("Transfer-Encoding", [])
                    or response.headers.get_all("Content-Encoding", ["identity"]) != ["identity"]
                    or lengths != [str(entry.size)]):
                raise LibraryError("SOURCE")
            yield response
            return
        finally:
            if response is not None:
                response.close()
            connection.close()
    raise LibraryError("SOURCE")


_MODEL_SQL = """CREATE TABLE models (
    catalog_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('missing','unverified','staged_verified')),
    sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, checked_at INTEGER NOT NULL)"""
_JOB_SQL = """CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY, catalog_id TEXT NOT NULL, state TEXT NOT NULL,
    bytes_received INTEGER NOT NULL, error_code TEXT, started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL)"""


def _admit_schema(connection):
    """Atomic first initialization, including known-empty interrupted starts.

    An existing unknown schema, populated partial schema or wrong version is
    never reset or repaired. The lifetime library flock is already held.
    """
    expected = {"jobs": _JOB_SQL, "models": _MODEL_SQL}
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        records = connection.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        objects = {name: sql for kind, name, sql in records if kind == 'table'}
        if len(objects) != len(records):
            raise LibraryError("UNAVAILABLE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if objects == expected and version == 1:
            return
        if (version != 0 or not objects.keys() <= expected.keys()
                or any(sql != expected[name] for name, sql in objects.items())):
            raise LibraryError("UNAVAILABLE")
        # These identifiers are closed source constants, never database input.
        for name in ("jobs", "models"):
            if name in objects and connection.execute(
                    "SELECT 1 FROM jobs LIMIT 1" if name == "jobs" else "SELECT 1 FROM models LIMIT 1").fetchone():
                raise LibraryError("UNAVAILABLE")
        for name in ("models", "jobs"):
            if name not in objects:
                connection.execute(expected[name])
        connection.execute("PRAGMA user_version=1")


class _Store:
    """Owner-private, descriptor-admitted SQLite; separate from all telemetry."""
    def __init__(self, root):
        self.root = root
        self.directory = self.descriptor = self.connection = self.lockfile = None
        try:
            if sys.platform != "linux" or os.geteuid() == 0:
                raise LibraryError("UNAVAILABLE")
            import fcntl
            root = storage._absolute_database_path(root / "library.sqlite3", "MODEL_LIBRARY").parent
            self.root = root
            self.directory = storage._open_private_directory(root, create=True, prefix="MODEL_LIBRARY")
            self.lockfile = os.open("library.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    0o600, dir_fd=self.directory)
            _file_stat(os.fstat(self.lockfile))
            try:
                fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LibraryError("BUSY") from None
            path = root / "library.sqlite3"
            self.descriptor, _ = storage._open_private_database(
                path, self.directory, writable=True, create=True, prefix="MODEL_LIBRARY",
                normalize_writable_mode=False)
            storage._validate_sqlite_sidecars(path, self.directory, writable=True, prefix="MODEL_LIBRARY")
            if os.fstat(self.descriptor).st_size > MAX_DATABASE_BYTES:
                raise LibraryError("UNAVAILABLE")
            selected, anchor = storage._writable_sqlite_connection_path(self.descriptor, path, "MODEL_LIBRARY")
            self.connection = storage._connect_verified_sqlite(
                f"{selected.as_uri()}?mode=rw&cache=private", path, self.descriptor, self.directory,
                "MODEL_LIBRARY", timeout=2)
            storage._validate_connection_path(self.connection, path, "MODEL_LIBRARY", anchor=anchor)
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA journal_mode=DELETE")
            self.connection.execute("PRAGMA max_page_count=256")
            if self.connection.execute("PRAGMA page_size").fetchone()[0] != 4096:
                raise LibraryError("UNAVAILABLE")
            _admit_schema(self.connection)
            storage._validate_sqlite_sidecars(path, self.directory, writable=True, prefix="MODEL_LIBRARY")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        for name in ("descriptor", "lockfile", "directory"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def job(self, identifier, entry, state, received=0, code=None):
        now = int(time.time())
        with self.connection:
            self.connection.execute("""INSERT INTO jobs VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,
                bytes_received=excluded.bytes_received,error_code=excluded.error_code,updated_at=excluded.updated_at""",
                (identifier, entry.id, state, received, code, now, now))

    def model(self, entry, state):
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO models VALUES (?,?,?,?,?)",
                                    (entry.id, state, entry.digest, entry.size, int(time.time())))


def _file_stat(info, *, links=1):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != links or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise LibraryError("FILE")
    return info


def _same(a, b):
    return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (
        b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns)


class ModelLibrary:
    def __init__(self, home):
        self.root = Path(home) / ".local/share/megalodon/model-library"
        self._lock = Lock()
        self._operation = Lock()
        self._stop = Event()
        self._view = dict(schema=SCHEMA, catalog=[entry.public() for entry in CATALOG],
                          models=[], jobs=[], state="unchecked", free_bytes=None,
                          reserve_bytes=RESERVE_BYTES, message="Check staged files or choose an explicit download.")

    def snapshot(self):
        with self._lock:
            return deepcopy(self._view)

    def _update(self, **values):
        with self._lock:
            self._view.update(values)

    def cancel(self):
        self._stop.set()

    def prepare(self):
        # Called before publishing/scheduling the explicit support job, so a
        # cancellation arriving before its worker starts cannot be lost.
        self._stop.clear()

    def _progress(self, identifier, entry, state, received=0, code=None):
        self._update(state=state, active=dict(job_id=identifier, catalog_id=entry.id, state=state,
                     bytes_received=received, error_code=code),
                     message=ERRORS[code] if code else {
                         "downloading": "Downloading the pinned model file…",
                         "verifying": "Checking model size and SHA-256…",
                         "staged_verified": "File staged and verified. It has not been imported or activated.",
                     }.get(state, "Checking the private model library…"))

    def _readback(self, store):
        models = []
        for identifier, state, digest, size, checked in store.connection.execute("SELECT * FROM models LIMIT 9"):
            entry = artifact(identifier)
            if (state not in ("missing", "unverified", "staged_verified") or digest != entry.digest or size != entry.size
                    or type(checked) is not int or checked < 0):
                raise LibraryError("UNAVAILABLE")
            models.append(dict(catalog_id=identifier, state=state, checked_at=checked))
        if len(models) > len(CATALOG):
            raise LibraryError("UNAVAILABLE")
        jobs = []
        for row in store.connection.execute("SELECT * FROM jobs ORDER BY started_at DESC,job_id DESC LIMIT 65"):
            identifier, catalog_id, state, received, code, started, updated = row
            entry = artifact(catalog_id)
            if (type(identifier) is not str or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier)
                    or state not in {"downloading", "verifying", "staged_verified", "failed", "cancelled", "interrupted"}
                    or type(received) is not int or not 0 <= received <= entry.size
                    or (code is not None and code not in ERRORS)
                    or type(started) is not int or type(updated) is not int or min(started, updated) < 0):
                raise LibraryError("UNAVAILABLE")
            jobs.append(dict(job_id=identifier, catalog_id=catalog_id, state=state,
                             bytes_received=received, error_code=code, started_at=started, updated_at=updated))
        if len(jobs) > MAX_JOBS:
            raise LibraryError("UNAVAILABLE")
        free = os.fstatvfs(store.directory).f_bavail * os.fstatvfs(store.directory).f_frsize
        self._update(models=models, jobs=jobs[:16], free_bytes=free)

    def _reconcile(self, store):
        # The lifetime flock proves no other cooperating staging worker is live.
        with store.connection:
            store.connection.execute("UPDATE jobs SET state='interrupted',error_code='INTERRUPTED',updated_at=? "
                                     "WHERE state IN ('downloading','verifying')", (int(time.time()),))
        for entry in CATALOG:
            try:
                info = os.stat(entry.id + ".part", dir_fd=store.directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if info.st_nlink == 2:
                # Crash between exclusive link-publication and partial unlink:
                # only these two exact names may account for both links.
                _file_stat(info, links=2)
                final = os.stat(entry.id + ".gguf", dir_fd=store.directory, follow_symlinks=False)
                if not _same(info, final):
                    raise LibraryError("FILE")
            else:
                _file_stat(info)
            if info.st_size > entry.size:
                raise LibraryError("FILE")
            os.unlink(entry.id + ".part", dir_fd=store.directory)
            os.fsync(store.directory)
        self._readback(store)

    def _existing(self, store, entry, deadline):
        name = entry.id + ".gguf"
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=store.directory)
        except FileNotFoundError:
            return False
        try:
            before = _file_stat(os.fstat(fd))
            if before.st_size != entry.size:
                raise LibraryError("SIZE")
            digest = sha256()
            received = 0
            while received < entry.size:
                _check(self._stop, deadline)
                data = os.read(fd, min(CHUNK_BYTES, entry.size - received))
                if not data:
                    raise LibraryError("SIZE")
                received += len(data)
                digest.update(data)
            if digest.hexdigest() != entry.digest:
                raise LibraryError("DIGEST")
            if not _same(before, os.fstat(fd)) or not _same(before, os.stat(
                    name, dir_fd=store.directory, follow_symlinks=False)):
                raise LibraryError("FILE")
            _check(self._stop, deadline)
            return True
        finally:
            os.close(fd)

    def _download(self, store, entry, identifier, deadline):
        free = os.fstatvfs(store.directory)
        if free.f_bavail * free.f_frsize < entry.size + RESERVE_BYTES:
            raise LibraryError("NO_SPACE")
        partial, final = entry.id + ".part", entry.id + ".gguf"
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=store.directory)
        received = 0
        original = os.fstat(fd)
        try:
            _file_stat(original)
            _check(self._stop, deadline)
            store.model(entry, "unverified")
            digest = sha256()
            with _response(entry, self._stop, deadline) as response:
                checkpoint = time.monotonic()
                while received < entry.size:
                    _check(self._stop, deadline)
                    data = response.read1(min(CHUNK_BYTES, entry.size - received))
                    _check(self._stop, deadline)
                    if not data:
                        raise LibraryError("SIZE")
                    if len(data) > min(CHUNK_BYTES, entry.size - received):
                        raise LibraryError("SIZE")
                    digest.update(data)
                    view = memoryview(data)
                    while view:
                        _check(self._stop, deadline)
                        written = os.write(fd, view)
                        if written <= 0:
                            raise LibraryError("FILE")
                        view = view[written:]
                    received += len(data)
                    self._progress(identifier, entry, "downloading", received)
                    if time.monotonic() - checkpoint >= 1:
                        store.job(identifier, entry, "downloading", received)
                        checkpoint = time.monotonic()
            _check(self._stop, deadline)
            self._progress(identifier, entry, "verifying", received)
            store.job(identifier, entry, "verifying", received)
            if digest.hexdigest() != entry.digest:
                raise LibraryError("DIGEST")
            os.fsync(fd)
            info = _file_stat(os.fstat(fd))
            if info.st_size != entry.size or not _same(info, os.stat(
                    partial, dir_fd=store.directory, follow_symlinks=False)):
                raise LibraryError("FILE")
            _check(self._stop, deadline)
            # Exclusive publication: never replace an existing final file.
            os.link(partial, final, src_dir_fd=store.directory, dst_dir_fd=store.directory, follow_symlinks=False)
            os.unlink(partial, dir_fd=store.directory)
            if not _same(os.fstat(fd), os.stat(final, dir_fd=store.directory, follow_symlinks=False)):
                raise LibraryError("FILE")
            os.fsync(store.directory)
        finally:
            os.close(fd)
            try:
                info = os.stat(partial, dir_fd=store.directory, follow_symlinks=False)
                if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                    os.unlink(partial, dir_fd=store.directory)
                    os.fsync(store.directory)
            except FileNotFoundError:
                pass

    def execute(self, identifier=None):
        """None means explicit offline check; an ID means explicit online stage."""
        entry = artifact(identifier) if identifier is not None else None
        if not self._operation.acquire(blocking=False):
            raise LibraryError("BUSY")
        deadline = time.monotonic() + DEADLINE_SECONDS
        job_id = secrets.token_hex(16)
        try:
            with _Store(self.root) as store:
                self._reconcile(store)
                if entry is None:
                    try:
                        for selected in CATALOG:
                            store.model(selected, "unverified")
                            store.model(selected, "staged_verified" if self._existing(store, selected, deadline) else "missing")
                    finally:
                        self._readback(store)
                    self._update(state="checked", active=None, message="Local staging checked. No download or model activation occurred.")
                    return self.snapshot()["message"]
                if store.connection.execute("SELECT count(*) FROM jobs").fetchone()[0] >= MAX_JOBS:
                    raise LibraryError("JOB_LIMIT")
                store.job(job_id, entry, "verifying")
                self._progress(job_id, entry, "verifying")
                try:
                    store.model(entry, "unverified")
                    if not self._existing(store, entry, deadline):
                        store.model(entry, "missing")
                        store.job(job_id, entry, "downloading")
                        self._progress(job_id, entry, "downloading")
                        self._download(store, entry, job_id, deadline)
                        # Read back the published file, not just the bytes fed
                        # into os.write, before a verified database receipt.
                        if not self._existing(store, entry, deadline):
                            raise LibraryError("FILE")
                    _check(self._stop, deadline)
                    # File fsync + exclusive publication precede a single success transaction.
                    with store.connection:
                        store.connection.execute("INSERT OR REPLACE INTO models VALUES (?,?,?,?,?)",
                                                (entry.id, "staged_verified", entry.digest, entry.size, int(time.time())))
                        store.connection.execute("UPDATE jobs SET state='staged_verified',bytes_received=?,updated_at=? WHERE job_id=?",
                                                (entry.size, int(time.time()), job_id))
                    self._progress(job_id, entry, "staged_verified", entry.size)
                except (LibraryError, OSError, http.client.HTTPException) as exc:
                    code = exc.code if isinstance(exc, LibraryError) else "NETWORK" if isinstance(
                        exc, (http.client.HTTPException, TimeoutError, ConnectionError, socket.gaierror, ssl.SSLError)) else "UNAVAILABLE"
                    received = min(entry.size, self.snapshot().get("active", {}).get("bytes_received", 0))
                    store.job(job_id, entry, "cancelled" if code == "CANCELLED" else "failed", received, code)
                    self._progress(job_id, entry, "cancelled" if code == "CANCELLED" else "failed", received, code)
                    raise LibraryError(code) from None
                finally:
                    self._readback(store)
                return self.snapshot()["message"]
        except (OSError, sqlite3.Error, storage.StorageSchemaError):
            self._update(state="failed", active=None, message=ERRORS["UNAVAILABLE"])
            raise LibraryError("UNAVAILABLE") from None
        except LibraryError as exc:
            self._update(state="cancelled" if exc.code == "CANCELLED" else "failed", message=str(exc))
            raise
        finally:
            self._operation.release()
