"""Package sources and signing keys: sources, keys, hooks and signature settings, from a stand-in root."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from megalodon import package_sources as ps
from megalodon import response_engine as re_


def packet(tag, body):
    """A new-format OpenPGP packet."""
    length = len(body)
    if length < 192:
        header = bytes([length])
    elif length < 8384:
        length -= 192
        header = bytes([(length >> 8) + 192, length & 0xFF])
    else:
        header = b"\xff" + length.to_bytes(4, "big")
    return bytes([0xC0 | tag]) + header + body


def mpi(value, bits):
    return bits.to_bytes(2, "big") + value.to_bytes((bits + 7) // 8, "big")


def public_key(seed, *, bits=3072, algorithm=1, created=1_700_000_000):
    """A version 4 public key packet body. Not a usable key: only its packet shape matters here."""
    modulus = int.from_bytes(hashlib.sha512(seed.encode()).digest() * (bits // 512 + 1), "big") >> 7
    modulus = (modulus % (1 << bits)) | (1 << (bits - 1)) | 1
    return bytes([4]) + created.to_bytes(4, "big") + bytes([algorithm]) + mpi(modulus, bits) + mpi(65537, 17)


def keyring(*keys):
    """Binary keyring bytes and the fingerprints of its keys, for (seed, user ID, bits) triples."""
    data, fingerprints = b"", []
    for seed, uid, bits in keys:
        body = public_key(seed, bits=bits)
        data += packet(6, body) + packet(13, uid.encode())
        fingerprints.append(hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper())
    return data, fingerprints


def armor(data):
    text = base64.b64encode(data).decode()
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    return "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: placeholder\n\n" + "\n".join(lines) + \
        "\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"


VENDOR = """Types: deb
URIs: https://packages.vendor.example/debian
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/vendor.asc
"""


@pytest.fixture
def root(tmp_path, monkeypatch):
    # The account running the tests stands in for root: on CI it is an ordinary user.
    monkeypatch.setattr(ps, "TRUSTED_UID", os.getuid())
    monkeypatch.setattr(ps, "TRUSTED_GID", os.getgid())
    base = tmp_path / "root"
    for folder in ("etc/apt/sources.list.d", "etc/apt/apt.conf.d", "etc/apt/trusted.gpg.d", "etc/apt/keyrings",
                   "usr/share/keyrings"):
        (base / folder).mkdir(parents=True)
    for folder in [base, *base.rglob("*")]:
        os.chmod(folder, 0o755)
    archive, _ = keyring(("archive", "Distribution Archive Signing Key", 4096))
    (base / "etc/apt/trusted.gpg.d/distribution.gpg").write_bytes(archive)
    (base / "usr/share/keyrings/distribution.gpg").write_bytes(archive)
    vendor, _ = keyring(("vendor", "Vendor Release Key", 4096))
    (base / "etc/apt/keyrings/vendor.asc").write_text(armor(vendor))
    (base / "etc/apt/sources.list").write_text(
        "# the distribution\ndeb [signed-by=/usr/share/keyrings/distribution.gpg] http://mirror.example/debian "
        "stable main\n")
    (base / "etc/apt/sources.list.d/vendor.sources").write_text(VENDOR)
    (base / "etc/apt/apt.conf.d/70debconf").write_text(
        '// Pre-configure all packages\nDPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};\n')
    (base / "etc/apt/apt.conf.d/50vendor").write_text(
        'Acquire::AllowInsecureRepositories "0";\nAcquire::Check-Valid-Until "true";\nDPkg::Post-Invoke "";\n')
    for path in base.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o644)
    return base


def rules(report):
    return sorted((f["severity"], f["rule_id"], f["subject"]) for f in report["findings"])


def test_keys_are_read_from_binary_and_armored_keyrings():
    data, fingerprints = keyring(("one", "First <one@example.org>", 4096), ("two", "Second", 1024))
    keys = ps.read_keys(data)
    assert [k["fingerprint"] for k in keys] == fingerprints
    assert [(k["algorithm"], k["bits"], k["uid"]) for k in keys] == [
        ("RSA", 4096, "First <one@example.org>"), ("RSA", 1024, "Second")]
    assert [k["fingerprint"] for k in ps.read_keys(armor(data).encode())] == fingerprints
    assert ps.weak(keys[1]) == "RSA 1024 bits" and ps.weak(keys[0]) is None
    # Old-format packets, as older gpg versions write them.
    body = public_key("old", bits=2048)
    old = bytes([0x99]) + len(body).to_bytes(2, "big") + body
    assert ps.read_keys(old)[0]["bits"] == 2048
    with pytest.raises(ValueError, match="keybox"):
        ps.read_keys(b"\x00\x00\x00\x20\x01\x01\x00\x00KBXf" + b"\x00" * 20)
    with pytest.raises(ValueError, match="not an OpenPGP keyring"):
        ps.read_keys(b"plain text, not a key")
    with pytest.raises(ValueError, match="truncated"):
        ps.read_keys(data[:40])


def test_apt_configuration_is_parsed_like_apt_config_dump():
    text = '''/* a block
    comment */
    APT::Get::AllowUnauthenticated "true"; // trailing comment
    # a comment line
    Acquire {
      https { Verify-Peer "false"; };
    };
    DPkg::Post-Invoke { "first"; "second"; };
    DPkg::Post-Invoke:: "third";
    #clear APT::Never
    '''
    assert ps.apt_options(text) == [
        ("apt::get::allowunauthenticated", "true"), ("acquire::https::verify-peer", "false"),
        ("dpkg::post-invoke", "first"), ("dpkg::post-invoke", "second"), ("dpkg::post-invoke::", "third")]


def test_a_clean_machine_has_no_findings_and_records_what_it_trusts(root, tmp_path):
    report = ps.baseline(tmp_path / "packages.json", root=str(root))
    assert report["findings"] == [] and report["gaps"] == []
    assert (report["sources"], report["keys"], report["hooks"], report["trusted_for_every_source"]) == (2, 2, 1, 1)
    assert oct((tmp_path / "packages.json").stat().st_mode & 0o777) == "0o600"
    assert ps.check(tmp_path / "packages.json")["findings"] == []
    with pytest.raises(ps.PackageSourcesError, match="exists"):
        ps.baseline(tmp_path / "packages.json", root=str(root))


def test_holes_already_there_are_reported_at_baseline(root, tmp_path):
    (root / "etc/apt/sources.list.d/local.list").write_text(
        "deb [trusted=yes] http://repo.internal.example/debian stable main\n"
        "deb [check-valid-until=yes allow-weak=no] https://ok.example/debian stable main\n")
    (root / "etc/apt/apt.conf.d/99unsafe").write_text(
        'APT::Get::AllowUnauthenticated "true";\nDPkg::Post-Invoke { "/tmp/placeholder-hook"; };\n')
    weak, _ = keyring(("legacy", "Legacy Key", 1024))
    (root / "etc/apt/trusted.gpg.d/legacy.gpg").write_bytes(weak)
    unused, _ = keyring(("retired", "Retired Key", 1024))
    (root / "usr/share/keyrings/retired-keys.gpg").write_bytes(unused)   # trusted by nothing: not reported
    (root / "etc/yum.repos.d").mkdir()
    (root / "etc/yum.repos.d/extra.repo").write_text(
        "[extra]\nname=Extra\nbaseurl=https://rpm.example/el9\ngpgcheck=0\n\n"
        "[signed]\nbaseurl=https://rpm.example/signed\ngpgcheck=1\ngpgkey=http://rpm.example/KEY\n\n"
        "[off]\nbaseurl=https://rpm.example/off\nenabled=0\ngpgcheck=0\n")
    os.chmod(root / "etc/apt/sources.list.d", 0o777)
    found = rules(ps.baseline(tmp_path / "packages.json", root=str(root)))
    weak_fp = ps.read_keys(weak)[0]["fingerprint"]
    assert found == [
        ("CRITICAL", "PACKAGE_CONFIG_WRITABLE", "file:/etc/apt/sources.list.d"),
        ("CRITICAL", "PACKAGE_SIGNATURES_OFF", "apt-source:http://repo.internal.example/debian"),
        ("CRITICAL", "PACKAGE_SIGNATURES_OFF", "apt:apt::get::allowunauthenticated"),
        ("CRITICAL", "PACKAGE_SIGNATURES_OFF", "dnf-repo:extra"),
        ("HIGH", "PACKAGE_MANAGER_HOOK_SUSPICIOUS",
         "hook:" + next(h for h in ps.snapshot(root=str(root))["hooks"] if "99unsafe" in h)),
        ("HIGH", "PACKAGE_SIGNATURE_CHECK_WEAKENED", "dnf-repo:signed:gpgkey"),
        ("MEDIUM", "WEAK_SIGNING_KEY", f"weak-key:{weak_fp}"),
    ], "the disabled repository, the vendor's '0' and 'yes' settings and the unused weak key are not reported"


def test_keys_sources_and_hooks_added_or_redirected(root, tmp_path):
    manifest = tmp_path / "packages.json"
    ps.baseline(manifest, root=str(root))
    # A key apt trusts for every source, and one that no source names yet.
    everywhere, (everywhere_fp,) = keyring(("intruder", "Placeholder Key", 4096))
    (root / "etc/apt/trusted.gpg.d/placeholder.asc").write_text(armor(everywhere))
    spare, (spare_fp,) = keyring(("spare", "Spare Key", 4096))
    (root / "usr/share/keyrings/spare.gpg").write_bytes(spare)
    # The distribution mirror moves; the vendor source trusts another key; a new source and hooks appear.
    (root / "etc/apt/sources.list").write_text(
        "deb [signed-by=/usr/share/keyrings/distribution.gpg] http://other-mirror.example/debian stable main\n")
    (root / "etc/apt/sources.list.d/vendor.sources").write_text(
        VENDOR.replace("/etc/apt/keyrings/vendor.asc", "/usr/share/keyrings/spare.gpg"))
    (root / "etc/apt/sources.list.d/new.list").write_text("deb https://new.example/debian stable main\n")
    (root / "etc/apt/apt.conf.d/80hooks").write_text(
        'APT::Update::Pre-Invoke { "/usr/local/bin/refresh-placeholder"; };\n'
        'DPkg::Post-Invoke:: "/var/tmp/placeholder";\n'
        'Acquire::https::mirror.example::Verify-Peer "false";\n')
    report = ps.check(manifest)
    hooks = {h["command"]: f"hook:{k}" for k, h in ps.snapshot(root=str(root))["hooks"].items()}
    assert rules(report) == sorted([
        ("CRITICAL", "PACKAGE_MANAGER_HOOK_ADDED", hooks["/var/tmp/placeholder"]),
        ("HIGH", "PACKAGE_MANAGER_HOOK_ADDED", hooks["/usr/local/bin/refresh-placeholder"]),
        ("HIGH", "PACKAGE_SOURCE_CHANGED", "source:apt deb https://packages.vendor.example/debian stable"),
        ("HIGH", "PACKAGE_SOURCE_REDIRECTED", "source:apt deb http://other-mirror.example/debian stable"),
        ("HIGH", "SIGNING_KEY_ADDED", f"key:{everywhere_fp}"),
        ("HIGH", "SIGNING_KEY_ADDED", f"key:{spare_fp}"),
        ("MEDIUM", "PACKAGE_SOURCE_ADDED", "source:apt deb https://new.example/debian stable"),
        ("MEDIUM", "PACKAGE_TRANSPORT_WEAKENED", "apt:acquire::https::verify-peer:mirror.example"),
    ])
    redirected = next(f for f in report["findings"] if f["rule_id"] == "PACKAGE_SOURCE_REDIRECTED")
    assert "http://mirror.example/debian → http://other-mirror.example/debian" in redirected["detail"]
    added = {f["fingerprint"]: f["detail"] for f in report["findings"] if f["rule_id"] == "SIGNING_KEY_ADDED"}
    assert "trusted for every source" in added[everywhere_fp] and "vendor.example" in added[spare_fp]
    assert report["removed"]["sources"] == ["apt deb http://mirror.example/debian stable"]
    assert ps.accept(manifest)["action"] == "accept" and ps.check(manifest)["findings"] == []


def test_a_key_moved_to_where_apt_trusts_it_for_everything(root, tmp_path):
    manifest = tmp_path / "packages.json"
    ps.baseline(manifest, root=str(root))
    vendor = (root / "etc/apt/keyrings/vendor.asc").read_text()
    (root / "etc/apt/trusted.gpg.d/vendor.asc").write_text(vendor)
    found = rules(ps.check(manifest))
    assert [r[:2] for r in found] == [("HIGH", "SIGNING_KEY_ADDED")]
    assert "now trusted for every source" in ps.check(manifest)["findings"][0]["detail"]


def test_inline_keys_and_unreadable_keyrings(root, tmp_path):
    data, (fingerprint,) = keyring(("inline", "Inline Key", 4096))
    inline = "\n".join(" " + (line or ".") for line in armor(data).splitlines())
    (root / "etc/apt/sources.list.d/inline.sources").write_text(
        "Types: deb\nURIs: https://inline.example/debian\nSuites: stable\nComponents: main\nSigned-By:\n"
        + inline + "\n\nTypes: deb\nURIs: https://disabled.example/debian\nSuites: stable\nEnabled: no\n")
    (root / "usr/share/keyrings/broken.gpg").write_bytes(b"not a keyring")
    state = ps.snapshot(root=str(root))
    assert state["keys"][fingerprint]["files"] == ["/etc/apt/sources.list.d/inline.sources (inline)"]
    assert state["sources"]["apt deb https://inline.example/debian stable"]["keys"] == [fingerprint]
    assert not any("disabled.example" in s for s in state["sources"])
    assert state["gaps"] == ["/usr/share/keyrings/broken.gpg: not an OpenPGP keyring"]


def test_rpm_keys_are_read_from_rpm_output():
    data, (fingerprint,) = keyring(("rpm", "Distribution (release key)", 4096))
    keys = ps._rpm_keys(lambda argv: armor(data) + "\n" + armor(data), [])
    assert [k["fingerprint"] for k in keys] == [fingerprint, fingerprint]
    assert ps._rpm_keys(lambda argv: "package gpg-pubkey is not installed\n", []) == []


def test_refused_baselines(root, tmp_path):
    manifest = tmp_path / "packages.json"
    with pytest.raises(ps.PackageSourcesError, match="run megalodon packages baseline"):
        ps.check(manifest)
    ps.baseline(manifest, root=str(root))
    os.chmod(manifest, 0o644)
    with pytest.raises(ps.PackageSourcesError, match="mode-600"):
        ps.check(manifest)
    os.chmod(manifest, 0o600)
    manifest.write_text(json.dumps(dict(schema="other")))
    with pytest.raises(ps.PackageSourcesError, match="unsupported format"):
        ps.check(manifest)


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys):
    manifest = tmp_path / "packages.json"
    ps.baseline(manifest, root=str(root))
    added, _ = keyring(("cli", "Placeholder Key", 4096))
    (root / "etc/apt/trusted.gpg.d/placeholder.gpg").write_bytes(added)
    (root / "etc/apt/sources.list.d/new.list").write_text("deb https://new.example/debian stable main\n")
    report = ps.check(manifest)
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=re_.package_signals(report), protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert [(d["playbook"], d["signal"]["rule_id"]) for d in decisions] == [
        ("package-trust-changed", "SIGNING_KEY_ADDED")], "the MEDIUM new source is below the playbook"
    assert decisions[0]["actions"][0]["action"] == "collect_evidence"
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(["packages", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 1
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]} == {
        "SIGNING_KEY_ADDED", "PACKAGE_SOURCE_ADDED"}


def test_the_last_assignment_is_the_one_apt_uses(root, tmp_path):
    # apt reads apt.conf.d in name order, then apt.conf: the later value wins.
    (root / "etc/apt/apt.conf.d/10weak").write_text('Acquire::AllowInsecureRepositories "true";\n')
    (root / "etc/apt/apt.conf.d/90restore").write_text('Acquire::AllowInsecureRepositories "false";\n')
    manifest = tmp_path / "packages.json"
    assert ps.baseline(manifest, root=str(root))["findings"] == [], "the effective value is false"
    (root / "etc/apt/apt.conf").write_text('Acquire::AllowInsecureRepositories "true";\n')
    assert rules(ps.check(manifest)) == [
        ("HIGH", "PACKAGE_SIGNATURE_CHECK_WEAKENED", "apt:acquire::allowinsecurerepositories")]


def test_a_relocation_is_followed_and_its_value_compared(root, tmp_path):
    vendor = root / "opt/vendor/sources"
    vendor.mkdir(parents=True)
    (vendor / "vendor.list").write_text("deb https://vendor.example/debian stable main\n")
    (root / "etc/apt/apt.conf.d/50parts").write_text('Dir::Etc::SourceParts "/opt/vendor/sources";\n')
    manifest = tmp_path / "packages.json"
    first = ps.baseline(manifest, root=str(root))
    assert rules(first) == [("HIGH", "PACKAGE_CONFIG_REDIRECTED", "apt:dir::etc::sourceparts")]
    assert "apt deb https://vendor.example/debian stable" in ps.snapshot(root=str(root))["sources"], \
        "apt reads sources from where it is told to"
    elsewhere = root / "opt/elsewhere/sources"
    elsewhere.mkdir(parents=True)
    (elsewhere / "other.list").write_text("deb https://other.example/debian stable main\n")
    (root / "etc/apt/apt.conf.d/50parts").write_text('Dir::Etc::SourceParts "/opt/elsewhere/sources";\n')
    assert rules(ps.check(manifest)) == [
        ("HIGH", "PACKAGE_CONFIG_REDIRECTED", "apt:dir::etc::sourceparts"),
        ("MEDIUM", "PACKAGE_SOURCE_ADDED", "source:apt deb https://other.example/debian stable")]


def test_folders_above_a_named_keyring_are_checked(root, tmp_path):
    keys, _ = keyring(("vendor-key", "Vendor Key", 4096))
    (root / "opt/vendor").mkdir(parents=True)
    (root / "opt/vendor/key.gpg").write_bytes(keys)
    (root / "srv/keys").mkdir(parents=True)
    (root / "srv/keys/real.gpg").write_bytes(keys)
    os.symlink("/srv/keys/real.gpg", root / "etc/apt/keyrings/linked.gpg")
    for folder in ("opt", "opt/vendor", "srv", "srv/keys"):
        os.chmod(root / folder, 0o755)
    (root / "etc/apt/sources.list.d/vendor.list").write_text(
        "deb [signed-by=/opt/vendor/key.gpg] https://vendor.example/debian stable main\n"
        "deb [signed-by=/etc/apt/keyrings/linked.gpg] https://linked.example/debian stable main\n")
    manifest = tmp_path / "packages.json"
    assert ps.baseline(manifest, root=str(root))["findings"] == []
    os.chmod(root / "opt/vendor", 0o777)       # anyone can swap the keyring without touching the file
    os.chmod(root / "srv/keys", 0o777)         # nor the file a symlinked keyring leads to
    assert rules(ps.check(manifest)) == [
        ("CRITICAL", "PACKAGE_CONFIG_WRITABLE", "file:/opt/vendor"),
        ("CRITICAL", "PACKAGE_CONFIG_WRITABLE", "file:/srv/keys")]
