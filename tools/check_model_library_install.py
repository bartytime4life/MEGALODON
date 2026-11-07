"""Explicit read-only source check; no installed MEGALODON imports or execution."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
from itertools import islice
import json
import os
from pathlib import Path
import stat

BASELINE = "ba3303eb0df043a2a6a5d6a88a89cff1970c5ba4"
SCHEMA = "megalodon-model-library-install-observation-v1"
MAX_FILE_BYTES = 1024 * 1024
EXPECTED = {
    "model_library.py": "c8c7ea8202009b465e2849db46ec268ffe0eb834f893bf5c3e35cef63dce57c0",
    "dashboard_model_library.py": "18732fbcb35ce19555e7ba3f4b9780e98e5a35760842c222afe5865d6b3ea706",
    "support_config.py": "4b846dae37e525113b01ce68a92b0ebc8336e857601f172bd165697488b2fe6b",
    "dashboard_support_config.py": "634415ec1418535e28b41d137dbbcb2f161be5015e9394b0d944e8184815c2f5",
    "model_artifact.py": "f02ad3756661d60548cb35c96593cbc0373f9faba64ae09a97640bc167725a9f",
    "local_model_runtime.py": "9e0bc58b0f2937cdbb19702b66f2684e3012ba8e931a449d19c67e7b12c67405",
}


class CheckError(ValueError):
    pass


def managed_package(home=None, data_home=None):
    """Locate one standard managed release, never search unrelated directories."""
    home = Path.home() if home is None else Path(home)
    root = (Path(data_home) if data_home else home / ".local/share") / "megalodon"
    try:
        release = (root / "current").resolve(strict=True)
        release.relative_to((root / "releases").resolve(strict=True))
        found = list(islice((release / "venv/lib").glob("python*/site-packages/megalodon"), 2))
    except (OSError, ValueError, RuntimeError):
        raise CheckError("INSTALLATION_UNAVAILABLE") from None
    if len(found) != 1:
        raise CheckError("INSTALLATION_UNAVAILABLE" if not found else "AMBIGUOUS_INSTALLATION")
    return found[0]


@contextmanager
def directory(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith("//"):
        raise CheckError("ABSOLUTE_PACKAGE_DIRECTORY_REQUIRED")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def file_observation(parent, name, expected):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FILE_BYTES:
            return dict(file=name, state="UNSAFE_OR_OVERSIZED")
        digest, count = sha256(), 0
        while True:
            data = os.read(fd, min(65536, before.st_size - count + 1))
            if not data:
                break
            count += len(data)
            if count > before.st_size:
                return dict(file=name, state="CHANGED")
            digest.update(data)
        if (count != before.st_size or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            return dict(file=name, state="CHANGED")
        value = digest.hexdigest()
        return dict(file=name, state="MATCH" if value == expected else "MISMATCH", sha256=value, size_bytes=count,
                    _identity=identity(before))
    except FileNotFoundError:
        return dict(file=name, state="MISSING")
    except OSError:
        return dict(file=name, state="UNAVAILABLE")
    finally:
        if fd is not None:
            os.close(fd)


def observe(package):
    result = dict(schema=SCHEMA, expected_source_commit=BASELINE, state="UNAVAILABLE", files=[],
                  scope="six_package_source_files_at_observation", runtime_acceptance="NOT_EVALUATED",
                  authority=dict(network=False, writes=False, imports_installed_package=False,
                                 starts_model=False, changes_services=False))
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        return dict(result, error_code="UNSUPPORTED_PLATFORM")
    try:
        with directory(package) as parent:
            pinned = os.fstat(parent)
            result["files"] = [file_observation(parent, name, expected) for name, expected in EXPECTED.items()]
            for row in result["files"]:
                previous = row.pop("_identity", None)
                if previous is not None and identity(os.stat(row["file"], dir_fd=parent, follow_symlinks=False)) != previous:
                    raise CheckError("SOURCE_FILES_CHANGED")
            with directory(package) as current:
                if (pinned.st_dev, pinned.st_ino) != (os.fstat(current).st_dev, os.fstat(current).st_ino):
                    raise CheckError("PACKAGE_DIRECTORY_CHANGED")
        result["state"] = "SOURCE_FILES_MATCH" if all(r["state"] == "MATCH" for r in result["files"]) else "SOURCE_FILES_DO_NOT_MATCH"
    except (CheckError, OSError) as exc:
        result.update(files=[], error_code=str(exc) if isinstance(exc, CheckError) else "PACKAGE_UNAVAILABLE")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, help="explicit actual installed megalodon package directory")
    args = parser.parse_args(argv)
    try:
        package = args.package_dir or managed_package(data_home=os.environ.get("XDG_DATA_HOME"))
        result = observe(package)
    except CheckError as exc:
        result = dict(schema=SCHEMA, state="UNAVAILABLE", expected_source_commit=BASELINE, error_code=str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "SOURCE_FILES_MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
