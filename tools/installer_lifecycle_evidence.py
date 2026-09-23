"""Real Linux installer rehearsal in disposable paths, never host acceptance."""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile


# Reuse the bounded subprocess, file, canonical JSON and clean-source checks.
_spec = importlib.util.spec_from_file_location(
    "installer_evidence_common", Path(__file__).with_name("installed_recovery_evidence.py")
)
_common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_common)
EvidenceError, require = _common.EvidenceError, _common.require
canonical, digest, read_bounded = _common.canonical, _common.digest, _common.read_bounded
command, source_identity = _common.command, _common.source_identity
MAX_RECEIPT = 8192
LOCK = "constraints/build-linux-cp312.txt"
CHECKS = {
    "initial_install": "real_release_ready",
    "same_source_replacement": "new_real_release_selected_previous_retained",
    "missing_launcher_repair": "restored_exact_bytes",
    "modified_artifact": "repair_and_uninstall_refused_without_mutation",
    "manifest_failure": "injected_after_real_release_activation",
    "rollback": "selection_manifest_artifacts_and_release_set_preserved",
    "installed_cli": "isolated_outside_checkout_after_install_replacement_and_rollback",
    "data_and_settings": "preserved_through_every_phase",
    "uninstall": "managed_code_and_artifacts_removed",
    "temporary_paths": "removed",
}
EXCLUSIONS = [
    "host_installation", "desktop_launch", "hud_or_services", "capture", "firewall",
    "models", "cross_version_upgrade", "physical_power_loss", "disk_full",
    "windows_or_macos", "release_publication", "operator_acceptance",
    "independent_acceptance", "artifact_authentication",
]


def locked_wheels(checkout):
    raw = read_bounded(checkout / LOCK, MAX_RECEIPT)
    result = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9-]*)==([0-9.]+) --hash=sha256:([0-9a-f]{64})", line)
        require(match is not None, "BUILD_LOCK_FORMAT")
        name, version, sha256 = match.groups()
        filename = name.replace("-", "_") + "-" + version + "-py3-none-any.whl"
        require(filename not in result, "BUILD_LOCK_DUPLICATE")
        result[filename] = "sha256:" + sha256
    require(len(result) == 4, "BUILD_LOCK_SET")
    return digest(raw), result


def wheelhouse_identity(checkout, wheelhouse):
    lock_sha256, expected = locked_wheels(checkout)
    require(not wheelhouse.is_symlink() and wheelhouse.is_dir(), "WHEELHOUSE_TYPE")
    require({path.name for path in wheelhouse.iterdir()} == set(expected), "WHEELHOUSE_SET")
    wheels = []
    for name, expected_digest in sorted(expected.items()):
        raw = read_bounded(wheelhouse / name)
        require(digest(raw) == expected_digest, "WHEELHOUSE_DIGEST")
        wheels.append({"filename": name, "sha256": expected_digest, "size_bytes": len(raw)})
    return {"lock_sha256": lock_sha256, "wheels": wheels}


def native_identity():
    require(sys.platform == "linux" and os.geteuid() != 0, "NON_ROOT_LINUX_REQUIRED")
    require(platform.machine() == "x86_64" and sys.version_info[:2] == (3, 12), "PLATFORM_PROFILE")
    require(sys.flags.isolated == 1, "ISOLATED_PYTHON_REQUIRED")
    return {"os": "linux", "architecture": "x86_64", "python": platform.python_version(), "non_root": True}


def source_package_identity(checkout):
    package = checkout / "megalodon"
    files = {}
    for path in package.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files[path.relative_to(package).as_posix()] = digest(read_bounded(path)).removeprefix("sha256:")
    require(0 < len(files) < 2048, "SOURCE_PACKAGE_LIMIT")
    tree = ast.parse(read_bounded(package / "__init__.py", MAX_RECEIPT))
    versions = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    require(len(versions) == 1, "SOURCE_PACKAGE_VERSION")
    # Match the isolated probe's digest over the sorted relative-file map.
    return {"distribution": "megalodon-defense", "version": versions[0],
            "source_package_sha256": digest(canonical(files).removesuffix(b"\n"))}


def temporary_paths(root, installer):
    """Pass every destination explicitly; never reassign HOME or use host paths."""
    app = root / "application"
    return installer.InstallPaths(
        app=app, releases=app / "releases", current=app / "current",
        manifest=app / "install.json", data=app / "data", config=root / "config",
        settings=root / "config/settings.toml", hud_launcher=root / "bin/megalodon-hud",
        manager_launcher=root / "bin/megalodon-manage", desktop_entry=root / "desktop/megalodon.desktop",
        icon=root / "icons/megalodon.svg",
    )


PROBE = r"""
import hashlib, importlib.metadata, json, pathlib, sys
import megalodon
source = pathlib.Path(sys.argv[1]).resolve()
installed = pathlib.Path(megalodon.__file__).resolve().parent
prefix = pathlib.Path(sys.prefix).resolve()
assert sys.flags.isolated == 1 and sys.prefix != sys.base_prefix
assert installed.is_relative_to(prefix) and not installed.is_relative_to(source)
assert not pathlib.Path.cwd().resolve().is_relative_to(source)
def files(root):
    result = {}
    for path in root.rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            assert not path.is_symlink() and path.stat().st_size <= 8 * 1024 * 1024
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert 0 < len(result) < 2048
    return result
expected = files(source / 'megalodon')
assert files(installed) == expected
dist = importlib.metadata.distribution('megalodon-defense')
assert dist.version == megalodon.__version__
direct = json.loads(dist.read_text('direct_url.json'))
assert direct.get('dir_info') == {} and direct.get('url') == source.as_uri()
print(json.dumps({'distribution':'megalodon-defense', 'version':dist.version,
    'source_package_sha256':'sha256:' + hashlib.sha256(json.dumps(expected,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()}))
"""


def installed_probe(paths, checkout, root):
    python = paths.current / "venv/bin/python"
    package = json.loads(command([str(python), "-I", "-c", PROBE, str(checkout)], root))
    help_text = command([str(python), "-I", "-c", _common.CLI_BOOTSTRAP, "--help"], root)
    require(b"MEGALODON" in help_text and b"--help" in help_text, "INSTALLED_CLI")
    command([str(python), "-I", "-m", "pip", "check"], root)
    return package


def rehearsal(checkout, wheelhouse, root):
    # The caller has verified this clean checkout and these exact build wheels.
    # Import only its implementation; the release builder and user checks stay real.
    sys.path.insert(0, str(checkout))
    from megalodon import local_install as installer

    installer._require_supported_user()
    paths = temporary_paths(root, installer)
    for name in tuple(os.environ):
        if name.startswith("PIP_"):
            os.environ.pop(name)
    os.environ.update(PIP_NO_INDEX="1", PIP_FIND_LINKS=str(wheelhouse))
    first = installer.install(checkout, paths)
    package = installed_probe(paths, checkout, root)
    require(installer.status(paths)[0] == 0, "INITIAL_INSTALL")
    require(not any(paths.data.iterdir()), "INSTALL_CREATED_DATA")
    marker = paths.data / "synthetic-marker.txt"
    marker.write_bytes(b"synthetic installer lifecycle data\n")
    marker.chmod(0o600)
    # Make preservation meaningful: use operator-edited, valid settings.
    paths.settings.write_bytes(paths.settings.read_bytes() + b"\n# synthetic operator setting\n")
    preserved = (marker.read_bytes(), paths.settings.read_bytes())

    def preservation():
        require((marker.read_bytes(), paths.settings.read_bytes()) == preserved, "PRESERVATION")
        require(stat.S_IMODE(paths.settings.stat().st_mode) == 0o600, "SETTINGS_MODE")

    second = installer.install(checkout, paths)
    require(second["active_release"] != first["active_release"]
            and second["previous_release"] == first["active_release"]
            and len(second["releases"]) == 2, "REPLACEMENT")
    require(installed_probe(paths, checkout, root) == package, "REPLACEMENT_PACKAGE")
    preservation()

    original_launcher = paths.hud_launcher.read_bytes()
    paths.hud_launcher.unlink()
    require(installer.status(paths)[0] == 2, "MISSING_LAUNCHER_STATUS")
    require(installer.repair(paths)["status"] == "ready", "REPAIR")
    require(paths.hud_launcher.read_bytes() == original_launcher, "REPAIR_BYTES")
    preservation()

    def selection():
        return (paths.current.readlink(), paths.manifest.read_bytes(),
                {name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                 for name, path in installer._artifact_paths(paths).items()},
                sorted(path.name for path in paths.releases.iterdir()))

    desktop = paths.desktop_entry.read_bytes()
    paths.desktop_entry.write_bytes(desktop + b"# synthetic user change\n")
    modified = selection()
    for operation in (installer.repair, installer.uninstall):
        try:
            operation(paths)
        except installer.InstallError:
            pass
        else:
            raise EvidenceError("MODIFIED_ARTIFACT_ACCEPTED")
        require(selection() == modified, "REFUSAL_MUTATED_INSTALLATION")
        preservation()
    paths.desktop_entry.write_bytes(desktop)

    before_failure = selection()
    real_write = installer._atomic_write
    injections = []

    class InjectedManifestFailure(OSError):
        pass

    def fail_manifest(path, raw, mode):
        if path == paths.manifest:
            # Failure is after activation, with a third real importable release.
            require(paths.current.readlink() != before_failure[0], "FAILURE_BEFORE_ACTIVATION")
            require(len(list(paths.releases.iterdir())) == 3, "FAILED_RELEASE_NOT_CREATED")
            require(installed_probe(paths, checkout, root) == package, "FAILED_RELEASE_PACKAGE")
            injections.append(True)
            raise InjectedManifestFailure("synthetic manifest write failure")
        return real_write(path, raw, mode)

    installer._atomic_write = fail_manifest
    try:
        try:
            installer.install(checkout, paths)
        except InjectedManifestFailure:
            pass
        else:
            raise EvidenceError("MANIFEST_FAILURE_NOT_EXERCISED")
    finally:
        installer._atomic_write = real_write
    require(injections == [True] and selection() == before_failure, "ROLLBACK")
    require(installer.status(paths)[0] == 0, "ROLLBACK_STATUS")
    require(installed_probe(paths, checkout, root) == package, "ROLLBACK_PACKAGE")
    preservation()

    require(installer.uninstall(paths)["status"] == "removed", "UNINSTALL")
    require(installer.status(paths)[0] == 1, "UNINSTALL_STATUS")
    require(not paths.releases.exists() and not paths.manifest.exists()
            and not os.path.lexists(paths.current)
            and not any(os.path.lexists(path) for path in installer._artifact_paths(paths).values()),
            "UNINSTALL_REMAINS")
    preservation()
    return package


def validate(receipt, checkout, commit, tree):
    require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "status", "source", "platform", "build_inputs", "package", "checks", "exclusions"
    }, "RECEIPT_SHAPE")
    require(receipt["schema"] == "native-installer-lifecycle-v1"
            and receipt["status"] == "same_source_rehearsal_passed", "RECEIPT_STATUS")
    require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (commit, tree)), "SOURCE_PIN")
    require(canonical(receipt["source"]) == canonical({"commit": commit, "tree": tree,
                                                     "working_tree_dirty": False}), "SOURCE_BINDING")
    require(canonical(receipt["checks"]) == canonical(CHECKS)
            and receipt["exclusions"] == EXCLUSIONS, "RECEIPT_CLAIMS")
    profile = receipt["platform"]
    require(isinstance(profile, dict) and set(profile) == {"os", "architecture", "python", "non_root"}
            and profile["os"] == "linux" and profile["architecture"] == "x86_64"
            and profile["non_root"] is True and isinstance(profile["python"], str)
            and re.fullmatch(r"3\.12\.[0-9]+", profile["python"]), "RECEIPT_PLATFORM")
    package = receipt["package"]
    require(isinstance(package, dict) and set(package) == {"distribution", "version", "source_package_sha256"}
            and package["distribution"] == "megalodon-defense"
            and isinstance(package["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", package["version"])
            and isinstance(package["source_package_sha256"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", package["source_package_sha256"]), "RECEIPT_PACKAGE")
    require(package == source_package_identity(checkout), "RECEIPT_PACKAGE_BINDING")
    inputs = receipt["build_inputs"]
    lock_sha256, expected = locked_wheels(checkout)
    require(isinstance(inputs, dict) and set(inputs) == {"lock_sha256", "wheels"}
            and inputs["lock_sha256"] == lock_sha256 and isinstance(inputs["wheels"], list)
            and len(inputs["wheels"]) == len(expected), "RECEIPT_BUILD_INPUTS")
    for wheel, (name, sha256) in zip(inputs["wheels"], sorted(expected.items())):
        require(isinstance(wheel, dict) and set(wheel) == {"filename", "sha256", "size_bytes"}
                and wheel["filename"] == name and wheel["sha256"] == sha256
                and type(wheel["size_bytes"]) is int and 0 < wheel["size_bytes"] <= _common.MAX_FILE,
                "RECEIPT_WHEEL")


def verify(raw, checkout, commit, tree):
    require(len(raw) <= MAX_RECEIPT, "RECEIPT_LIMIT")
    receipt = json.loads(raw)
    require(canonical(receipt) == raw, "RECEIPT_CANONICAL")
    validate(receipt, checkout, commit, tree)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--wheelhouse", type=Path, required=True)
    worker = commands.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("--wheelhouse", type=Path, required=True)
    worker.add_argument("--root", type=Path, required=True)
    commands.add_parser("verify").add_argument("receipt", type=Path)
    args = parser.parse_args()
    checkout = args.checkout.resolve(strict=True)
    source = source_identity(checkout, args.expected_commit, args.expected_tree)
    if args.action == "verify":
        verify(read_bounded(args.receipt, MAX_RECEIPT), checkout, args.expected_commit, args.expected_tree)
        print('{"status":"same_source_receipt_binding_verified","authentication":"not_performed"}')
        return
    profile = native_identity()
    inputs = wheelhouse_identity(checkout, args.wheelhouse)
    if args.action == "_worker":
        require(args.root.resolve() == Path.cwd().resolve() and not args.root.is_symlink()
                and stat.S_IMODE(args.root.stat().st_mode) == 0o700
                and not any(args.root.iterdir()), "PRIVATE_EMPTY_WORKER_ROOT")
        package = rehearsal(checkout, args.wheelhouse, args.root)
        (args.root / "result.json").write_bytes(canonical(package))
        return
    with tempfile.TemporaryDirectory(prefix="megalodon-installer-lifecycle-") as directory:
        root = Path(directory)
        require(not root.is_relative_to(checkout), "CHECKOUT_CWD")
        command([sys.executable, "-I", str(Path(__file__).resolve()), "--checkout", str(checkout),
                 "--expected-commit", args.expected_commit, "--expected-tree", args.expected_tree,
                 "_worker", "--wheelhouse", str(args.wheelhouse.resolve()), "--root", str(root)], root,
                timeout=1200)
        package = json.loads(read_bounded(root / "result.json", MAX_RECEIPT))
    require(not root.exists(), "TEMPORARY_PATHS_REMAIN")
    require(wheelhouse_identity(checkout, args.wheelhouse) == inputs, "BUILD_INPUTS_CHANGED")
    source_identity(checkout, args.expected_commit, args.expected_tree)
    receipt = {"schema": "native-installer-lifecycle-v1", "status": "same_source_rehearsal_passed",
               "source": source, "platform": profile, "build_inputs": inputs, "package": package,
               "checks": CHECKS, "exclusions": EXCLUSIONS}
    raw = canonical(receipt)
    verify(raw, checkout, args.expected_commit, args.expected_tree)
    sys.stdout.buffer.write(raw)


if __name__ == "__main__":
    try:
        main()
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AssertionError) as exc:
        # Never emit private paths, environment values, or build output.
        reason = str(exc) if isinstance(exc, EvidenceError) else "REFUSED"
        print("INSTALLER_LIFECYCLE:" + reason, file=sys.stderr)
        raise SystemExit(1)
