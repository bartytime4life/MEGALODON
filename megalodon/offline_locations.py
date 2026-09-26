"""Optional, read-only coarse IP regions from an operator-installed MMDB file.

The dashboard never downloads a database or contacts an IP lookup service.
"""

from __future__ import annotations

from ipaddress import ip_address
import math
import os
from pathlib import Path
import stat
from typing import Any

from .storage import StorageSchemaError, _open_private_directory


MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_LOOKUP_IPS = 20
SCHEMA = "dashboard-offline-locations-v1"


class OfflineLocations:
    """Hold one validated, immutable-in-memory database snapshot for a HUD launch."""

    def __init__(self, reader: Any):
        self._reader = reader

    @classmethod
    def open(cls, path: str | Path) -> "OfflineLocations":
        selected = Path(path)
        if not selected.is_absolute() or selected.name in {"", ".", ".."} or ".." in selected.parts:
            raise ValueError("offline location database requires an absolute path")
        try:
            import maxminddb
        except ImportError:
            raise ValueError("offline location database requires the optional maxminddb package") from None
        try:
            directory = _open_private_directory(selected.parent, create=False, prefix="OFFLINE_LOCATIONS")
        except StorageSchemaError as exc:
            raise ValueError(str(exc)) from None
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(selected.name, flags, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= MAX_DATABASE_BYTES
                    or (os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077))):
                raise ValueError("offline location database must be an owner-private regular file up to 128 MiB")
            reader = maxminddb.open_database(descriptor, mode=maxminddb.Mode.FD)
            return cls(reader)
        except Exception as exc:
            raise ValueError("offline location database could not be opened safely") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)

    def close(self) -> None:
        self._reader.close()

    def lookup(self, ips: list[str]) -> dict[str, object]:
        addresses = validate_lookup_ips(ips)
        locations: dict[str, dict[str, object]] = {}
        for text, address in addresses:
            if not address.is_global:
                continue
            try:
                record = self._reader.get(text)
            except ValueError:
                # An IPv6 lookup against an IPv4-only file is a miss.
                continue
            if not isinstance(record, dict):
                continue
            point = record.get("location")
            if not isinstance(point, dict):
                continue
            latitude, longitude = point.get("latitude"), point.get("longitude")
            if (type(latitude) not in (int, float) or type(longitude) not in (int, float)
                    or not math.isfinite(latitude) or not math.isfinite(longitude)
                    or not -90 <= latitude <= 90 or not -180 <= longitude <= 180):
                continue
            country = record.get("country")
            iso = country.get("iso_code") if isinstance(country, dict) else None
            label = f"Approx. region {iso.upper()}" if isinstance(iso, str) and len(iso) == 2 and iso.isascii() and iso.isalpha() else "Approx. region"
            locations[text] = {"latitude": round(latitude / 5) * 5,
                               "longitude": round(longitude / 5) * 5, "label": label}
        return {"schema": SCHEMA, "status": "available", "source": "offline database", "locations": locations}


def validate_lookup_ips(ips: object) -> list[tuple[str, Any]]:
    if type(ips) is not list or len(ips) > MAX_LOOKUP_IPS:
        raise ValueError("invalid offline location request")
    result = []
    seen = set()
    for value in ips:
        if type(value) is not str or not 2 <= len(value) <= 45 or value != value.strip():
            raise ValueError("invalid offline location request")
        try:
            address = ip_address(value)
        except ValueError:
            raise ValueError("invalid offline location request") from None
        canonical = str(address)
        if value != canonical or canonical in seen:
            raise ValueError("invalid offline location request")
        seen.add(canonical)
        result.append((canonical, address))
    return result


def unconfigured(ips: object) -> dict[str, object]:
    validate_lookup_ips(ips)
    return {"schema": SCHEMA, "status": "unconfigured", "source": "none", "locations": {}}
