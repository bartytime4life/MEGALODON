"""Account-free local IP context; only this PC's public address is discovered online.

Peer lookups use a private DB-IP Lite monthly snapshot. No packet or peer address
is submitted to an Internet service. All network work is explicit or scheduled by
an enabled background monitor, never performed by a GET handler.
"""
from datetime import datetime, timezone
import gzip
import hashlib
from http.client import HTTPSConnection
from ipaddress import ip_address
import json
import os
from pathlib import Path
import tempfile
from threading import Event, Lock
import time

from .local_install import _owned_directory, _regular_owned_file, _atomic_write
from .managed_capture import now
from .offline_locations import OfflineLocations, MAX_DATABASE_BYTES


class Geography:
    def __init__(self, home):
        self.root = Path(home) / '.local/share/megalodon/geography'
        self.path = self.root / 'dbip-city-lite.mmdb'
        self.receipt = self.root / 'source.json'
        self._lock = Lock()
        self._refresh_lock = Lock()
        self._closed = Event()
        self._reader = None
        self._cache = {}
        self._source_month = None
        self._state = dict(status='missing', source='DB-IP City Lite', build_date=None,
                           updated_at=None, anchor=None, anchor_checked_at=None,
                           message='Enable location data to prepare approximate geography.',
                           attribution_url='https://db-ip.com')
        try:
            if self.path.exists() and self.receipt.exists():
                receipt = json.loads(_regular_owned_file(self.receipt, maximum=2048))
                self._load(receipt)
        except (OSError, ValueError):
            self._state['message'] = 'Saved geography could not be validated; refresh location data.'

    def _load(self, receipt):
        if (type(receipt) is not dict or receipt.get('source') != 'DB-IP City Lite'
                or type(receipt.get('downloaded_at')) is not str):
            raise ValueError('Invalid geography receipt.')
        datetime.fromisoformat(receipt['downloaded_at'])
        reader = OfflineLocations.open(self.path)
        metadata = reader.metadata()
        if metadata.database_type != 'DBIP-City-Lite':
            reader.close()
            raise ValueError('Unexpected geographic database type.')
        build = datetime.fromtimestamp(metadata.build_epoch, timezone.utc)
        with self._lock:
            if self._closed.is_set():
                reader.close()
                raise ValueError('Geography is closed.')
            old = self._reader
            self._reader = reader
            self._cache.clear()
            self._source_month = build.strftime('%Y-%m')
            self._state.update(status='ready', build_date=build.isoformat().replace('+00:00','Z'),
                               updated_at=receipt.get('downloaded_at'), message='Peer locations are estimated locally from DB-IP City Lite.')
            if old:
                old.close()

    def snapshot(self):
        with self._lock:
            return json.loads(json.dumps(self._state))

    def lookup(self, address):
        if not ip_address(address).is_global:
            return None
        with self._lock:
            if self._reader is None:
                return None
            if address not in self._cache:
                if len(self._cache) >= 2048:
                    self._cache.clear()
                self._cache[address] = self._reader.detail(address)
            value = self._cache[address]
            return dict(value) if value else None

    def refresh(self):
        if self._closed.is_set():
            return
        if not self._refresh_lock.acquire(blocking=False):
            return
        try:
            month = datetime.now(timezone.utc).strftime('%Y-%m')
            using_saved = False
            if self._source_month != month:
                with self._lock:
                    self._state.update(status='updating', message='Preparing the free monthly IP-location database…')
                try:
                    self._download(month)
                except Exception:
                    if self._reader is None:
                        raise
                    using_saved = True
            connection = HTTPSConnection('api64.ipify.org', timeout=8)
            try:
                connection.request('GET', '/?format=json', headers={'User-Agent':'MEGALODON-local-geography/1'})
                response = connection.getresponse()
                data = response.read(513)
                if response.status != 200 or len(data) > 512:
                    raise ValueError('Public internet address unavailable.')
                address = ip_address(json.loads(data)['ip'])
                if not address.is_global:
                    raise ValueError('Public internet address unavailable.')
                anchor = self.lookup(str(address))
                with self._lock:
                    message = ('Your marker estimates this internet exit, which may be an ISP or VPN location.' if anchor else 'The public internet address has no location in this database.')
                    if using_saved:
                        message += ' Monthly update unavailable; using the dated saved database.'
                    self._state.update(anchor=anchor, anchor_checked_at=now(), status='ready',
                                       message=message)
            finally:
                connection.close()
        except Exception:
            with self._lock:
                self._state.update(status='ready' if self._reader else 'unavailable', anchor=None,
                                   message='Location refresh unavailable. Peer lookups use the saved database when present; this PC remains unlocated.')
        finally:
            self._refresh_lock.release()

    def _download(self, month):
        _owned_directory(self.root, private=True)
        connection = HTTPSConnection('download.db-ip.com', timeout=15)
        temporary = None
        try:
            connection.request('GET', f'/free/dbip-city-lite-{month}.mmdb.gz', headers={'User-Agent':'MEGALODON-local-geography/1'})
            response = connection.getresponse()
            size = int(response.getheader('Content-Length', '0'))
            if response.status != 200 or not 1 <= size <= MAX_DATABASE_BYTES:
                raise ValueError('Geography download unavailable or too large.')
            deadline = time.monotonic() + 180
            digest = hashlib.sha256()
            total = 0
            fd, temporary = tempfile.mkstemp(prefix='.dbip-', suffix='.mmdb', dir=self.root)
            with os.fdopen(fd, 'wb') as output, gzip.GzipFile(fileobj=response) as archive:
                while True:
                    chunk = archive.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DATABASE_BYTES or time.monotonic() > deadline or self._closed.is_set():
                        raise ValueError('Geography download bound exceeded.')
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            candidate = OfflineLocations.open(temporary)
            try:
                meta = candidate.metadata()
                build_month = datetime.fromtimestamp(meta.build_epoch, timezone.utc).strftime('%Y-%m')
                if meta.database_type != 'DBIP-City-Lite' or build_month != month:
                    raise ValueError('Geography release did not match.')
            finally:
                candidate.close()
            os.replace(temporary, self.path)
            temporary = None
            receipt = dict(source='DB-IP City Lite', month=month, downloaded_at=now(), sha256=digest.hexdigest(), bytes=total,
                           license='CC BY 4.0', attribution_url='https://db-ip.com')
            _atomic_write(self.receipt, json.dumps(receipt).encode(), 0o600)
            self._load(receipt)
        finally:
            connection.close()
            if temporary:
                Path(temporary).unlink(missing_ok=True)

    def close(self):
        self._closed.set()
        with self._lock:
            if self._reader:
                self._reader.close()
                self._reader = None
