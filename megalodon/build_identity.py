"""Content identity for packaged code and reference assets; no host identifiers."""
from hashlib import sha256
from pathlib import Path
import os


def package_digest(root):
    root = Path(root)
    digest = sha256()
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Package identity cannot include symbolic links')
        if not path.is_file():continue
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(sha256(path.read_bytes()).digest())
    return digest.hexdigest()


# Freeze at process startup: changing the installation selector cannot make an
# old running process claim the new package's identity.
PACKAGE_DIGEST = package_digest(Path(__file__).parent)
# A read-only directory descriptor identifies the imported release in /proc
# even after the `current` selector changes. No file is written or locked.
_PACKAGE_DIRECTORY_FD = os.open(Path(__file__).resolve().parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) if os.name=='posix' else None
