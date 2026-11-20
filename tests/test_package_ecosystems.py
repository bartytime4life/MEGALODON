"""Package sources beyond apt and dnf: pip, npm, flatpak and snap, read from a stand-in root."""
from __future__ import annotations

import os

from megalodon import package_sources as ps
from test_package_sources import armor, keyring, root  # noqa: F401


def place(base, path, text, mode=0o644):
    target = base / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    for folder in [target.parent, *target.parent.parents]:
        if str(folder).startswith(str(base)) and folder.exists():
            os.chmod(folder, 0o755)
    target.write_bytes(text) if isinstance(text, bytes) else target.write_text(text)
    os.chmod(target, mode)
    return target


def found(report):
    return sorted((f["severity"], f["rule_id"], f["subject"]) for f in report["findings"])


def test_pip_indexes_redirects_extra_indexes_and_trusted_hosts(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/etc/pip.conf", "[global]\nindex-url = https://pypi.internal.example/simple\n")
    assert found(ps.baseline(manifest, root=str(root))) == [], "a private index over TLS is normal"
    place(root, "/etc/pip.conf", "[global]\nindex-url = https://pypi.attacker.example/simple\n"
                                 "extra-index-url = https://pypi.org/simple\ntrusted-host = pypi.attacker.example\n")
    report = ps.check(manifest, root=str(root))
    rules = {(f["rule_id"], f["severity"]) for f in report["findings"]}
    assert rules == {("PACKAGE_SOURCE_REDIRECTED", "HIGH"), ("PACKAGE_SOURCE_ADDED", "MEDIUM"),
                     ("PACKAGE_INDEX_MIXED", "MEDIUM"), ("PACKAGE_TRANSPORT_WEAKENED", "HIGH")}
    redirect = next(f for f in report["findings"] if f["rule_id"] == "PACKAGE_SOURCE_REDIRECTED")
    assert "pypi.internal.example" in redirect["detail"] and "pypi.attacker.example" in redirect["detail"]
    # An account's own settings, over plain HTTP, are told apart from the system's.
    ps.accept(manifest, root=str(root))
    place(root, "/home/dev/.config/pip/pip.conf", "[install]\nindex_url = http://mirror.example/simple\n")
    report = ps.check(manifest, root=str(root))
    weakened = [f for f in report["findings"] if f["rule_id"] == "PACKAGE_TRANSPORT_WEAKENED"]
    assert weakened and weakened[0]["severity"] == "HIGH" and "account dev" in weakened[0]["detail"]
    assert not [f for f in report["findings"] if "account root" in f["detail"]], \
        "accounts without settings of their own use the system's and are not listed"


def test_npm_registry_scopes_and_strict_ssl(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/usr/bin/npm", "#!/bin/sh\n", 0o755)
    ps.baseline(manifest, root=str(root))
    place(root, "/etc/npmrc", "registry=https://registry.attacker.example/\n"
                              "@corp:registry=https://npm.corp.example/\n")
    place(root, "/root/.npmrc", "strict-ssl=false\n", 0o600)
    report = ps.check(manifest, root=str(root))
    assert {(f["rule_id"], f["severity"]) for f in report["findings"]} == {
        ("PACKAGE_SOURCE_REDIRECTED", "HIGH"), ("PACKAGE_SOURCE_ADDED", "MEDIUM"),
        ("PACKAGE_TRANSPORT_WEAKENED", "HIGH")}
    redirect = next(f for f in report["findings"] if f["rule_id"] == "PACKAGE_SOURCE_REDIRECTED")
    assert "registry.npmjs.org" in redirect["detail"], "from the default registry"
    assert any("@corp:registry" in f["detail"] and "npm.corp.example" in f["detail"]
               for f in report["findings"] if f["rule_id"] == "PACKAGE_SOURCE_ADDED"), "a scope's own registry"
    assert "account root" in next(f["detail"] for f in report["findings"]
                                  if f["rule_id"] == "PACKAGE_TRANSPORT_WEAKENED")


def test_flatpak_remotes_their_keys_and_signature_checks(root, tmp_path):
    manifest = tmp_path / "packages.json"
    remote_keys, (fingerprint,) = keyring(("flathub", "Flathub Repo Signing Key", 4096))
    repo = "/var/lib/flatpak/repo"
    place(root, f"{repo}/flathub.trustedkeys.gpg", remote_keys)
    place(root, f"{repo}/config", '[core]\nrepo_version=1\n\n[remote "flathub"]\nurl=https://dl.flathub.org/repo/\n'
                                  'gpg-verify=true\n\n[remote "old"]\nurl=http://old.example/\ngpg-verify=false\n'
                                  'disable=true\n')
    assert found(ps.baseline(manifest, root=str(root))) == [], "a disabled remote installs nothing"
    state = ps.snapshot(root=str(root))
    flathub = next(sid for sid, s in state["sources"].items() if s["manager"] == "flatpak")
    assert state["keys"][fingerprint]["used_by"] == [flathub]
    extra_keys, (added,) = keyring(("intruder", "Totally Flathub", 4096))
    place(root, f"{repo}/flathub.trustedkeys.gpg", remote_keys + extra_keys)
    place(root, f"{repo}/config", '[core]\nrepo_version=1\n\n[remote "flathub"]\n'
                                  'url=https://mirror.attacker.example/repo/\ngpg-verify=false\n'
                                  'gpg-verify-summary=false\n\n[remote "tools"]\nurl=https://tools.example/repo/\n')
    report = ps.check(manifest, root=str(root))
    assert {(f["rule_id"], f["severity"]) for f in report["findings"]} == {
        ("PACKAGE_SIGNATURES_OFF", "CRITICAL"), ("PACKAGE_SIGNATURE_CHECK_WEAKENED", "HIGH"),
        ("PACKAGE_SOURCE_REDIRECTED", "HIGH"), ("PACKAGE_SOURCE_ADDED", "MEDIUM"), ("SIGNING_KEY_ADDED", "HIGH")}
    assert next(f for f in report["findings"] if f["rule_id"] == "SIGNING_KEY_ADDED")["fingerprint"] == added


def test_snaps_installed_unchecked_and_snapd_sent_elsewhere(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/var/lib/snapd/snaps/core22_1380.snap", b"")
    place(root, "/var/lib/snapd/snaps/helper_x1.snap", b"")
    report = ps.baseline(manifest, root=str(root))
    assert found(report) == [("CRITICAL", "PACKAGE_SIGNATURES_OFF", "snap:helper")], \
        "a hole already there is reported at baseline"
    place(root, "/etc/systemd/system/snapd.service.d/store.conf",
          '[Service]\nEnvironment="SNAPPY_FORCE_API_URL=https://store.attacker.example/"\n')
    assert found(ps.check(manifest, root=str(root))) == [("HIGH", "PACKAGE_CONFIG_REDIRECTED", "snapd:SNAPPY_FORCE_API_URL")]


def test_an_older_baseline_does_not_report_the_built_in_defaults(root, tmp_path):
    """After an upgrade, a tool's default index is first seen: it is not a setting anyone added."""
    manifest = tmp_path / "packages.json"
    ps.baseline(manifest, root=str(root))
    place(root, "/usr/bin/pip3", "#!/bin/sh\n", 0o755)
    place(root, "/usr/bin/npm", "#!/bin/sh\n", 0o755)
    assert found(ps.check(manifest, root=str(root))) == []
    place(root, "/etc/pip.conf", "[global]\nindex-url = https://pypi.attacker.example/simple\n")
    assert [f["rule_id"] for f in ps.check(manifest, root=str(root))["findings"]] == ["PACKAGE_SOURCE_ADDED"]


def test_settings_others_can_change(root, tmp_path):
    place(root, "/etc/pip.conf", "[global]\nindex-url = https://pypi.org/simple\n", 0o666)
    report = ps.baseline(tmp_path / "packages.json", root=str(root))
    assert ("CRITICAL", "PACKAGE_CONFIG_WRITABLE", "file:/etc/pip.conf") in found(report)
