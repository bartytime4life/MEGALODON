"""Explicit read-only source check; no installed MEGALODON imports or execution."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat

BASELINE = "41aac8cdcd25837857f6651e8d046cb70b21e8f5"
SCHEMA = "megalodon-model-library-install-observation-v1"
MAX_FILE_BYTES = 1024 * 1024
EXPECTED = {
    "model_library.py": "45c3611b2f67c33c02d9cd4b0bad051df1a984a38fa3092fe08da0dac7d09f31",
    "dashboard_model_library.py": "9fd66c7cd7d439fac3451c00ca1407188318ff459d34a5a881501f6a23cf8847",
    "support_config.py": "d251d355ab8d1d84593b10d452cab0744cfff77d3de565cba93f14cccf3f6b0a",
    "dashboard_support_config.py": "2f70b61c691f35140d06d91fba696e88c8a9f0681a3824c86b83a45124e0210a",
    "model_artifact.py": "f02ad3756661d60548cb35c96593cbc0373f9faba64ae09a97640bc167725a9f",
    "local_model_runtime.py": "9e0bc58b0f2937cdbb19702b66f2684e3012ba8e931a449d19c67e7b12c67405",
}


class CheckError(ValueError):
    pass


def managed_package(home=None, data_home=None):
    """Discovery only; CLI observations keep managed_installation open too."""
    with managed_installation(home, data_home) as package:
        return package


def selector(parent):
    before = os.stat("current", dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISLNK(before.st_mode):
        raise CheckError("INSTALLATION_UNAVAILABLE")
    target = os.readlink("current", dir_fd=parent)
    after = os.stat("current", dir_fd=parent, follow_symlinks=False)
    if identity(before) != identity(after):
        raise CheckError("INSTALLATION_CHANGED")
    return identity(before), target


@contextmanager
def managed_installation(home=None, data_home=None):
    """Pin real ancestry and the one permitted selector link through readback."""
    home = Path.home() if home is None else Path(home)
    root = (Path(data_home) if data_home is not None else home / ".local/share") / "megalodon"
    try:
        with ExitStack() as stack:
            pinned = []
            discovery = []
            def pin(path, *, watch_children=False):
                fd = stack.enter_context(directory(path))
                info = os.fstat(fd)
                pinned.append((path, (info.st_dev, info.st_ino)))
                if watch_children:
                    discovery.append((fd, identity(info)))
                return fd

            parent = pin(root)
            releases = root / "releases"
            pin(releases)  # Never resolve a link masquerading as this directory.
            selection = selector(parent)
            target = Path(selection[1])
            release = Path(os.path.normpath(target if target.is_absolute() else root / target))
            if (release.parent != releases
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", release.name) is None):
                raise CheckError("INSTALLATION_UNAVAILABLE")
            pin(release)
            lib = release / "venv/lib"
            lib_fd = pin(lib, watch_children=True)
            found = []
            with os.scandir(lib_fd) as entries:
                for count, entry in enumerate(entries):
                    if count >= 256:
                        raise CheckError("INSTALLATION_UNAVAILABLE")
                    if re.fullmatch(r"python3\.[0-9]+", entry.name) is None:
                        continue
                    version = lib / entry.name
                    pin(version, watch_children=True)
                    site_packages = version / "site-packages"
                    package = site_packages / "megalodon"
                    try:
                        # A missing package can later appear below an existing
                        # version/site-packages directory without changing lib.
                        pin(site_packages, watch_children=True)
                        pin(package)
                    except FileNotFoundError:
                        continue
                    found.append(package)
                    if len(found) > 1:
                        raise CheckError("AMBIGUOUS_INSTALLATION")
            if not found:
                raise CheckError("INSTALLATION_UNAVAILABLE")

            yield found[0]

            # Discard an otherwise matching file receipt if the selected
            # installation changed while files were being observed.
            try:
                for path, expected in pinned:
                    with directory(path) as current:
                        info = os.fstat(current)
                        if (info.st_dev, info.st_ino) != expected:
                            raise CheckError("INSTALLATION_CHANGED")
                for fd, expected in discovery:
                    if identity(os.fstat(fd)) != expected:
                        raise CheckError("INSTALLATION_CHANGED")
                # Check the selector last as well: path revalidation itself
                # must not leave an unobserved change to the selected release.
                if selector(parent) != selection:
                    raise CheckError("INSTALLATION_CHANGED")
            except (OSError, CheckError):
                raise CheckError("INSTALLATION_CHANGED") from None
    except OSError:
        raise CheckError("INSTALLATION_UNAVAILABLE") from None


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
        if args.package_dir is not None:
            result = observe(args.package_dir)
        else:
            with managed_installation(data_home=os.environ.get("XDG_DATA_HOME")) as package:
                result = observe(package)
    except CheckError as exc:
        result = dict(schema=SCHEMA, state="UNAVAILABLE", expected_source_commit=BASELINE, files=[], error_code=str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "SOURCE_FILES_MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
