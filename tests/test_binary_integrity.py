"""Program integrity: packaged programs checked against their package, and unpackaged ones against a baseline."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from megalodon import binary_integrity as bi

ME = os.geteuid()


def md5(data):
    return hashlib.md5(data).hexdigest()


class FakeSystem:
    """A merged-/usr system: /bin and /sbin link to /usr, with a dpkg database."""

    def __init__(self, root):
        self.root = root
        for folder in ("usr/bin", "usr/sbin", "usr/local/bin", "usr/lib/x86_64-linux-gnu/security",
                       "usr/share/doc/tool", "var/lib/dpkg/info"):
            (root / folder).mkdir(parents=True, exist_ok=True)
        os.symlink("usr/bin", root / "bin")
        os.symlink("usr/sbin", root / "sbin")
        self.packages: dict[str, tuple[str, dict[str, bytes]]] = {}

    def program(self, path, data, mode=0o755):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, mode)
        return target

    def package(self, name, version, files, *, listed=None, installed=True):
        """files: {path as the package lists it: content}; listed overrides recorded digests."""
        self.packages[name] = (version, files)
        for path, data in files.items():
            if data is not None:
                self.program(path, data, 0o644 if path.endswith((".so", ".gz")) or ".so." in path else 0o755)
        lines = "".join(f"{(listed or {}).get(path) or md5(data or b'')}  {path.lstrip('/')}\n"
                        for path, data in files.items())
        (self.root / f"var/lib/dpkg/info/{name}.md5sums").write_text(lines, encoding="utf-8")
        status = "install ok installed" if installed else "deinstall ok config-files"
        stanzas = [s for s in self._status() if not s.startswith(f"Package: {name}\n")]
        stanzas.append(f"Package: {name}\nStatus: {status}\nArchitecture: amd64\nVersion: {version}\n")
        (self.root / "var/lib/dpkg/status").write_text("\n".join(stanzas), encoding="utf-8")

    def _status(self):
        path = self.root / "var/lib/dpkg/status"
        return [s.strip("\n") + "\n" for s in path.read_text(encoding="utf-8").split("\n\n")] if path.exists() else []

    def options(self, **extra):
        return dict(root=str(self.root), owner_uid=ME, **extra)


@pytest.fixture
def system(tmp_path):
    fake = FakeSystem(tmp_path / "root")
    fake.package("coreutils", "9.4-3", {"/bin/ls": b"\x7fELF ls", "/usr/bin/cat": b"\x7fELF cat",
                                         "/usr/share/doc/tool/README.gz": b"docs"})
    fake.package("hello", "2.10-3", {"/usr/bin/hello": b"\x7fELF hello"})
    fake.package("libpam-modules", "1.5.3", {"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": b"\x7fELF pam"})
    fake.package("libkeyutils1", "1.6.3", {"/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10": b"\x7fELF keyutils"})
    fake.package("libfoo1", "1.0", {"/usr/lib/x86_64-linux-gnu/libfoo.so.1": b"\x7fELF foo"})
    return fake


def rules(report):
    return {(f["rule_id"], f["path"], f["severity"]) for f in report["findings"]}


# ------------------------------------------------------------- verify

def test_a_clean_system_verifies_and_merged_usr_paths_count_once(system):
    report = bi.verify(**system.options())
    assert report["findings"] == [] and report["gaps"] == []
    assert report["packaged"] == 5, "ls, cat, hello, the PAM module and libkeyutils; docs and libfoo are out of scope"
    assert report["files"] == 5


def test_a_trojaned_program_or_library_no_longer_matches_its_package(system):
    system.program("/usr/bin/ls", b"\x7fELF ls with a backdoor")
    system.program("/usr/bin/hello", b"\x7fELF hello changed")
    system.program("/usr/lib/x86_64-linux-gnu/security/pam_unix.so", b"\x7fELF pam that logs passwords", 0o644)
    system.program("/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10", b"\x7fELF keyutils changed", 0o644)
    report = bi.verify(**system.options())
    assert rules(report) == {
        ("PACKAGE_MISMATCH", "/usr/bin/ls", "CRITICAL"),
        ("PACKAGE_MISMATCH", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "CRITICAL"),
        ("PACKAGE_MISMATCH", "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10", "CRITICAL"),
        ("PACKAGE_MISMATCH", "/usr/bin/hello", "HIGH")}
    ls = next(f for f in report["findings"] if f["path"] == "/usr/bin/ls")
    assert ls["techniques"] == ["T1554", "T1014"] and ls["detail"]["package"] == "coreutils 9.4-3"
    assert report["findings"][0]["severity"] == "CRITICAL", "most severe first"


def test_other_libraries_are_verified_only_when_asked(system):
    system.program("/usr/lib/x86_64-linux-gnu/libfoo.so.1", b"\x7fELF foo changed", 0o644)
    assert bi.verify(**system.options())["findings"] == []
    assert rules(bi.verify(**system.options(all_libraries=True))) == {
        ("PACKAGE_MISMATCH", "/usr/lib/x86_64-linux-gnu/libfoo.so.1", "HIGH")}


def test_missing_programs_removed_packages_and_diversions(system):
    os.unlink(system.root / "usr/bin/cat")
    os.unlink(system.root / "usr/share/doc/tool/README.gz")
    assert rules(bi.verify(**system.options())) == {("PACKAGE_FILE_MISSING", "/usr/bin/cat", "LOW")}, \
        "a missing document is not reported"
    system.package("oldtool", "1.0", {"/usr/bin/oldtool": None}, installed=False)
    # Package "wrapper" diverts hello's /usr/bin/hello to /usr/bin/hello.distrib and installs its own.
    system.program("/usr/bin/hello.distrib", b"\x7fELF hello")
    system.package("wrapper", "1.0", {"/usr/bin/hello": b"\x7fELF wrapper"})
    (system.root / "var/lib/dpkg/diversions").write_text(
        "/usr/bin/hello\n/usr/bin/hello.distrib\nwrapper\n", encoding="utf-8")
    report = bi.verify(**system.options())
    assert rules(report) == {("PACKAGE_FILE_MISSING", "/usr/bin/cat", "LOW")}, \
        "neither the removed package nor the diverted file is a mismatch"


def test_writable_and_foreign_owned_programs(system):
    os.chmod(system.root / "usr/bin/hello", 0o757)
    assert rules(bi.verify(**system.options())) == {("PROGRAM_WRITABLE", "/usr/bin/hello", "HIGH")}
    os.chmod(system.root / "usr/bin/hello", 0o755)
    assert {f["rule_id"] for f in bi.verify(root=str(system.root), owner_uid=ME + 1)["findings"]} == \
        {"PROGRAM_WRITABLE"}, "a program not owned by the expected owner"


def test_no_dpkg_database_is_a_gap_not_a_clean_result(tmp_path):
    bare = FakeSystem(tmp_path / "bare")
    bare.program("/usr/bin/tool", b"\x7fELF tool")
    report = bi.verify(**bare.options())
    assert report["packaged"] == 0 and report["files"] == 1
    assert report["gaps"] == ["no dpkg database: packaged programs are not verified (on RPM systems, use rpm -Va)"]


# ------------------------------------------------------------- baseline and check

def test_baseline_catches_unpackaged_programs_and_edited_package_records(system, tmp_path):
    manifest = tmp_path / "conf" / "binaries.json"
    result = bi.baseline(manifest, **system.options())
    assert result["files"] == 5 and stat.S_IMODE(manifest.stat().st_mode) == 0o600
    with pytest.raises(bi.BinaryIntegrityError, match="exists"):
        bi.baseline(manifest, **system.options())
    assert bi.check(manifest, **system.options())["findings"] == []
    system.program("/usr/bin/update-helper", b"\x7fELF dropped")
    system.program("/usr/local/bin/tool", b"\x7fELF local")
    report = bi.check(manifest, **system.options())
    assert rules(report) == {("PROGRAM_ADDED", "/usr/bin/update-helper", "HIGH"),
                             ("PROGRAM_ADDED", "/usr/local/bin/tool", "MEDIUM")}
    bi.accept(manifest, **system.options())
    system.program("/usr/local/bin/tool", b"\x7fELF local v2")
    assert rules(bi.check(manifest, **system.options())) == {("PROGRAM_CHANGED", "/usr/local/bin/tool", "MEDIUM")}
    bi.accept(manifest, **system.options())
    # A package upgrade changes the file and its record together: not a finding.
    system.package("hello", "2.10-4", {"/usr/bin/hello": b"\x7fELF hello v2"})
    report = bi.check(manifest, **system.options())
    assert report["findings"] == [] and report["updated"] == [
        {"path": "/usr/bin/hello", "package": ["hello 2.10-3", "hello 2.10-4"]}]
    bi.accept(manifest, **system.options())
    # The same change without an upgrade: the record was edited to hide it.
    system.package("coreutils", "9.4-3", {"/bin/ls": b"\x7fELF ls hidden", "/usr/bin/cat": b"\x7fELF cat",
                                          "/usr/share/doc/tool/README.gz": b"docs"})
    assert bi.verify(**system.options())["findings"] == [], "package verification alone is fooled"
    assert rules(bi.check(manifest, **system.options())) == {("PACKAGE_RECORD_CHANGED", "/usr/bin/ls", "HIGH")}
    # A plain mismatch is reported once, not also as a change.
    system.program("/usr/bin/cat", b"\x7fELF cat changed")
    assert [f["rule_id"] for f in bi.check(manifest, **system.options())["findings"]
            if f["path"] == "/usr/bin/cat"] == ["PACKAGE_MISMATCH"]


def test_baseline_files_are_refused_when_unsafe(system, tmp_path):
    manifest = tmp_path / "binaries.json"
    with pytest.raises(bi.BinaryIntegrityError, match="run megalodon binaries baseline"):
        bi.check(manifest, **system.options())
    with pytest.raises(bi.BinaryIntegrityError):
        bi.accept(manifest, **system.options())
    bi.baseline(manifest, **system.options())
    os.chmod(manifest, 0o640)
    with pytest.raises(bi.BinaryIntegrityError, match="mode-600"):
        bi.check(manifest, **system.options())
    os.chmod(manifest, 0o600)
    manifest.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    with pytest.raises(bi.BinaryIntegrityError, match="unsupported format"):
        bi.check(manifest, **system.options())


def test_cli_exit_codes(system, tmp_path, monkeypatch, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    real = bi.snapshot
    monkeypatch.setattr(bi, "snapshot", lambda **options: real(**{**options, **system.options()}))
    assert code("binaries", "verify") == 0
    system.program("/usr/bin/hello", b"\x7fELF hello changed")
    capsys.readouterr()
    assert code("binaries", "verify") == 1
    assert [f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]] == ["PACKAGE_MISMATCH"]
    manifest = str(tmp_path / "binaries.json")
    assert code("binaries", "check", "--manifest", manifest) == 2
    assert code("binaries", "baseline", "--manifest", manifest) == 1, "baseline reports what is already wrong"


def test_a_packaged_program_replaced_by_a_link_is_still_checked(system, tmp_path):
    manifest = tmp_path / "binaries.json"
    bi.baseline(manifest, **system.options())
    payload = system.program("/tmp/.x/ls", b"\x7fELF replacement")
    os.unlink(system.root / "usr/bin/ls")
    os.symlink(payload, system.root / "usr/bin/ls")
    for report in (bi.verify(**system.options()), bi.check(manifest, **system.options())):
        found = [f for f in report["findings"] if f["path"] == "/usr/bin/ls"]
        assert [(f["rule_id"], f["severity"]) for f in found] == [("PACKAGE_MISMATCH", "CRITICAL")]
        assert found[0]["detail"]["replaced_by_link"] == str(payload)
    # A relative link to another system program is a replacement too.
    os.unlink(system.root / "usr/bin/ls")
    os.symlink("cat", system.root / "usr/bin/ls")
    assert ("PACKAGE_MISMATCH", "/usr/bin/ls", "CRITICAL") in rules(bi.verify(**system.options()))
