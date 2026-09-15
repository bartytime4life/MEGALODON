"""Read-only origin check for the prepared CI sdist-test virtual environment.

Run with its Python's -I flag. This inspects distribution metadata, not imported
package code, and is neither a general environment scanner nor a sandbox.
"""
from importlib.metadata import PackageNotFoundError, distribution
import json
from pathlib import Path
import site
import sys

DEPENDENCIES = (
    "attrs", "build", "iniconfig", "jsonschema", "jsonschema-specifications",
    "packaging", "pluggy", "pygments", "pyproject-hooks", "pytest",
    "referencing", "rpds-py", "setuptools", "typing-extensions",
)


class EnvironmentCheckError(ValueError):
    """A fixed, non-sensitive CI diagnostic."""


def check_environment() -> dict[str, object]:
    prefix = Path(sys.prefix).resolve()
    if not sys.flags.isolated or prefix == Path(sys.base_prefix).resolve():
        raise EnvironmentCheckError("SDIST_ENV:NOT_ISOLATED")
    if site.ENABLE_USER_SITE is not False:
        raise EnvironmentCheckError("SDIST_ENV:USER_SITE_ENABLED")
    try:
        with (prefix / "pyvenv.cfg").open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("oversized configuration")
        values = [value.strip().lower() for line in raw.decode("utf-8").splitlines()
                  for key, separator, value in [line.partition("=")]
                  if separator and key.strip().lower() == "include-system-site-packages"]
    except (OSError, UnicodeError, ValueError):
        raise EnvironmentCheckError("SDIST_ENV:CONFIG_UNAVAILABLE") from None
    if values != ["false"]:
        raise EnvironmentCheckError("SDIST_ENV:SYSTEM_SITE_ENABLED")
    for name in DEPENDENCIES:
        try:
            origin = Path(distribution(name).locate_file("")).resolve()
        except PackageNotFoundError:
            raise EnvironmentCheckError("SDIST_ENV:MISSING_DEPENDENCY") from None
        except (OSError, TypeError, ValueError):
            raise EnvironmentCheckError("SDIST_ENV:INVALID_ORIGIN") from None
        if not origin.is_relative_to(prefix):
            raise EnvironmentCheckError("SDIST_ENV:EXTERNAL_DEPENDENCY")
    return {"schema": "sdist-environment-v1", "status": "passed",
            "dependency_count": len(DEPENDENCIES), "system_site_packages": False,
            "user_site_enabled": False}


def main() -> int:
    try:
        receipt = check_environment()
    except EnvironmentCheckError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("MEGALODON_SDIST_ENVIRONMENT " + json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
