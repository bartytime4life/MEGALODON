"""Synchronize generated pages into an exclusively owned, trusted Wiki checkout.

Only pages recorded in the last ownership manifest may be pruned. Preflight all
inputs before changing pages; write the manifest last. This is not a transaction:
I/O failure may leave the temporary checkout partially updated, so the caller
must stop before committing or pushing on failure. No network or Git operations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MANIFEST = ".megalodon-wiki-pages.json"
SCHEMA = "megalodon-wiki-pages-v1"
PAGE_NAME = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9_-]{0,119}|_Sidebar|_Footer)\.md")
MAX_PAGES = 256
MAX_PAGE_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class WikiSyncError(ValueError):
    """Refuse inconsistent ownership or unsafe filesystem inputs."""


def _directory(path: Path) -> Path:
    path = path.absolute()
    for part in (*reversed(path.parents), path):
        if not stat.S_ISDIR(part.lstat().st_mode):
            raise WikiSyncError("Wiki paths must use real directories, without symlinks.")
    return path


def _regular(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(mode):
        raise WikiSyncError("Wiki pages and manifest must be regular files, without symlinks.")
    return True


def _read(path: Path, limit: int) -> bytes:
    if not _regular(path):
        raise WikiSyncError("A required Wiki input is missing.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise WikiSyncError("Wiki input exceeds the supported size limit.")
    return data


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise WikiSyncError("Wiki ownership manifest contains duplicate fields.")
        value[key] = item
    return value


def _page_name(name: str) -> bool:
    return PAGE_NAME.fullmatch(name) is not None


def _ownership(path: Path) -> dict[str, str]:
    if not _regular(path):
        return {}
    try:
        value = json.loads(_read(path, MAX_MANIFEST_BYTES), object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError) as error:
        raise WikiSyncError("Wiki ownership manifest is not valid JSON.") from error
    if (not isinstance(value, dict) or set(value) != {"schema", "pages"}
            or value["schema"] != SCHEMA or not isinstance(value["pages"], dict)
            or not 1 <= len(value["pages"]) <= MAX_PAGES
            or any(not _page_name(name) or not isinstance(digest, str)
                   or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                   for name, digest in value["pages"].items())):
        raise WikiSyncError("Wiki ownership manifest has an unsupported shape.")
    return value["pages"]


def _write(path: Path, data: bytes) -> None:
    # Replacement also avoids modifying other names hard-linked to an old page.
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def synchronize(source: Path, destination: Path) -> None:
    """Copy current pages and prune only unchanged, formerly generated pages."""
    source, destination = _directory(source), _directory(destination)
    if source == destination or source in destination.parents or destination in source.parents:
        raise WikiSyncError("Generated pages and Wiki checkout must be separate directories.")
    pages = sorted(source.iterdir())
    if not 1 <= len(pages) <= MAX_PAGES or any(not _page_name(page.name) for page in pages):
        raise WikiSyncError("Generated Wiki input must contain only supported Markdown page names.")
    incoming = {page.name: _read(page, MAX_PAGE_BYTES) for page in pages}
    if not incoming.get("Home.md"):
        raise WikiSyncError("Generated Wiki input requires a nonempty Home.md.")
    previous = _ownership(destination / MANIFEST)
    # Inspect every affected path before any write or deletion, including pages
    # that will be replaced and previously owned pages already absent on disk.
    existing = {
        name: _read(destination / name, MAX_PAGE_BYTES) if _regular(destination / name) else None
        for name in incoming.keys() | previous.keys()
    }
    obsolete = sorted(previous.keys() - incoming.keys())
    for name in obsolete:
        if existing[name] is not None and hashlib.sha256(existing[name]).hexdigest() != previous[name]:
            raise WikiSyncError("An obsolete generated Wiki page was edited; reconcile it before publishing.")
    ownership = {"schema": SCHEMA, "pages": {
        name: hashlib.sha256(data).hexdigest() for name, data in incoming.items()
    }}
    manifest = (json.dumps(ownership, indent=2, sort_keys=True) + "\n").encode("utf-8")
    for name, data in incoming.items():
        target = destination / name
        if existing[name] != data:
            _write(target, data)
    for name in obsolete:
        if existing[name] is not None:
            (destination / name).unlink()
    manifest_path = destination / MANIFEST
    if not _regular(manifest_path) or _read(manifest_path, MAX_MANIFEST_BYTES) != manifest:
        _write(manifest_path, manifest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        synchronize(args.source, args.destination)
    except (OSError, WikiSyncError) as error:
        message = str(error) if isinstance(error, WikiSyncError) else "Wiki checkout I/O failed."
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
