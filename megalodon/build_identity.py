"""Content identity for packaged code and reference assets; no host identifiers."""
from hashlib import sha256
from pathlib import Path


def package_digest(root):
    root = Path(root)
    digest = sha256()
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc' or not path.is_file():
            continue
        if path.is_symlink():
            raise ValueError('Package identity cannot include symbolic links')
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(sha256(path.read_bytes()).digest())
    return digest.hexdigest()


# Freeze at process startup: changing the installation selector cannot make an
# old running process claim the new package's identity.
PACKAGE_DIGEST = package_digest(Path(__file__).parent)
