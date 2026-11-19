"""Exposed secrets: who can read keys, tokens and passwords, from a stand-in root. No real secret is used.

Every secret-shaped value is assembled at run time, so this file holds no literal token or key for scanners to flag.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from megalodon import response_engine as re_
from megalodon import secrets_scan as sc
from test_process_network import proc  # noqa: F401

GITHUB = "gh" + "p_" + "Zq7rT2" * 6
AWS = "AK" + "IA" + "QW3RTY7UIOPASDF2"
PASSWORD = "S3cr3t" + "Value9"


def private_key(cipher="none"):
    blob = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher.encode() + bytes(range(256))
    body = base64.b64encode(blob).decode()
    return ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
            + "\n-----END " + "OPENSSH PRIVATE KEY-----\n")


def put(root, path, text, mode=0o644):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    os.chmod(target, mode)
    return target


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    gid = os.getgid()
    put(base, "/etc/passwd", f"root:x:0:0::/root:/bin/sh\nalice:x:{os.getuid()}:{gid}::/home/alice:/bin/sh\n"
                             f"bob:x:{os.getuid() + 1}:{gid + 1}::/home/bob:/bin/sh\n")
    # The test account's own group stands in for alice's private group: nobody else is in it.
    put(base, "/etc/group", f"alice:x:{gid}:\nbob:x:{gid + 1}:\n")
    for folder in ("home/alice", "var/www/html", "opt", "tmp", "proc"):
        (base / folder).mkdir(parents=True, exist_ok=True)
    for folder in [base, *base.rglob("*")]:
        if folder.is_dir():
            os.chmod(folder, 0o755)
    return base


def scan(root, **kw):
    return sc.scan(str(root), **kw)


def rules(findings):
    return sorted((f["severity"], f["rule_id"], f["subject"]) for f in findings)


def test_secrets_are_recognized_and_never_shown():
    text = (f"token = {GITHUB}\naws_access_key_id = {AWS}\n{private_key()}"
            f"url = postgres://app:{PASSWORD}@db.internal/app\n")
    found = sc.secrets_in(text)
    assert [(kind, line) for kind, _s, _f, line in found] == [
        ("private key", 3), ("AWS access key", 2), ("GitHub token", 1), ("password in a URL", len(text.splitlines()))]
    shown = " ".join(s for _k, s, _f, _l in found)
    assert GITHUB not in shown and AWS not in shown and PASSWORD not in shown
    assert "40 characters, sha256 " in shown and f"password in a URL ({len(PASSWORD)} characters)" in shown, "passwords get no hash"
    assert [k for k, *_ in sc.secrets_in(private_key("aes256-ctr"))] == ["encrypted private key"]
    # Examples, placeholders and header strings in code are not secrets.
    quiet = ("PEM = '-----BEGIN " + "RSA PRIVATE KEY-----' % name + '-----END'\n"
             "db = postgres://user:password@localhost/x\nurl = https://me:${TOKEN}@host/x\n"
             "api = https://a:b3t7e9x2@example.com/\nid = " + "AK" + "IAIOSFODNN7EXAMPLE\n")
    assert sc.secrets_in(quiet) == []
    google = "key = AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    assert [k for k, *_ in sc.secrets_in(google)] == ["Google API key"]
    assert sc.secrets_in(google, passwords=False) == [], "SDKs ship public client keys in their code"


def test_who_can_read_a_file(root):
    accounts = sc._Accounts(str(root))
    reach = sc._Reach(str(root), accounts)
    open_file = put(root, "/home/alice/notes.conf", "x", 0o644)
    assert reach.who("/home/alice/notes.conf", open_file.stat()) == "everyone"
    os.chmod(root / "home/alice", 0o700)                              # nobody else can enter the home folder
    assert sc._Reach(str(root), accounts).who("/home/alice/notes.conf", open_file.stat()) is None
    os.chmod(root / "home/alice", 0o750)
    os.chmod(open_file, 0o640)
    assert sc._Reach(str(root), accounts).who("/home/alice/notes.conf", open_file.stat()) is None, \
        "the file's group is alice's own, with nobody else in it"
    put(root, "/etc/group", f"staff:x:{os.getgid()}:bob\n")
    shared = sc._Accounts(str(root))
    assert sc._Reach(str(root), shared).who("/home/alice/notes.conf", open_file.stat()) == "group staff"
    put(root, "/etc/group", f"ssl-cert:x:{os.getgid()}:bob\n")
    assert sc._Reach(str(root), sc._Accounts(str(root))).who("/home/alice/notes.conf", open_file.stat()) is None, \
        "ssl-cert members are meant to read TLS keys"


def test_web_roots_hand_out_what_is_under_them(root):
    put(root, "/var/www/html/.env", "APP_ENV=production\n")
    put(root, "/var/www/html/wp-config.php.bak", "<?php define('DB_PASSWORD', 'x');\n")
    put(root, "/var/www/html/backup/site.sql", "INSERT INTO users VALUES (1);\n")
    put(root, "/var/www/html/.htpasswd", "admin:$apr1$abc$def\n")
    put(root, "/var/www/html/assets/app.js", f"const token = '{GITHUB}';\n")
    put(root, "/var/www/html/index.php", f"<?php $t = '{GITHUB}';\n", 0o600)   # run by the server, not handed out
    put(root, "/var/www/html/index.html", "<p>hello</p>\n")
    put(root, "/var/www/html/.git/config", "[core]\n")
    findings, gaps = scan(root, search=("/var/www",))
    assert rules(findings) == [
        ("CRITICAL", "SECRET_FILE_IN_WEB_ROOT", "file:/var/www/html/.env"),
        ("CRITICAL", "SECRET_FILE_IN_WEB_ROOT", "file:/var/www/html/backup/site.sql"),
        ("CRITICAL", "SECRET_FILE_IN_WEB_ROOT", "file:/var/www/html/wp-config.php.bak"),
        ("CRITICAL", "SECRET_IN_WEB_ROOT", "file:/var/www/html/assets/app.js"),
        ("CRITICAL", "VERSION_CONTROL_IN_WEB_ROOT", "file:/var/www/html/.git"),
        ("HIGH", "SECRET_FILE_IN_WEB_ROOT", "file:/var/www/html/.htpasswd"),
    ] and gaps == []


def test_credential_files_and_keys_by_who_can_read_them(root):
    put(root, "/home/alice/.aws/credentials", f"[default]\naws_access_key_id = {AWS}\n")
    put(root, "/home/alice/.ssh/id_ed25519", private_key("aes256-ctr"))
    put(root, "/home/alice/.ssh/id_ed25519.pub", "ssh-ed25519 AAAA alice\n")
    put(root, "/etc/shadow", "root:*:19000:0:99999:7:::\n")
    put(root, "/opt/sdk/tests/data/server.key", private_key())                # a library's own test key
    findings, _ = scan(root, search=("/etc", "/home", "/opt"))
    assert rules(findings) == [
        ("CRITICAL", "CREDENTIAL_FILE_EXPOSED", "file:/etc/shadow"),
        ("CRITICAL", "CREDENTIAL_FILE_EXPOSED", "file:/home/alice/.aws/credentials"),
        ("HIGH", "PRIVATE_KEY_EXPOSED", "file:/home/alice/.ssh/id_ed25519"),
    ], "an encrypted key is one step lower; public keys and library test data are not secrets"
    # Readable only by root and the shadow group, as installed: nothing to report.
    put(root, "/etc/group", f"alice:x:{os.getgid()}:\nshadow:x:{os.getgid() + 5}:bob\n")
    os.chmod(root / "etc/shadow", 0o600)
    os.chmod(root / "home/alice", 0o700)
    assert scan(root, search=("/etc", "/home"))[0] == []


def test_tokens_in_readable_files_and_histories(root):
    put(root, "/home/alice/.bash_history", f"git push https://alice:{GITHUB}@github.com/x\n")
    put(root, "/etc/app/app.conf", f"database = postgres://app:{PASSWORD}@db.internal/app\n")
    put(root, "/opt/runtime/lib/uri.rb", f"# URI.parse('http://user:{PASSWORD}@db.internal/')\n")  # library docs
    put(root, "/tmp/private.conf", f"token = {GITHUB}\n", 0o600)                       # only its owner can read it
    findings, _ = scan(root, search=("/etc", "/home", "/opt", "/tmp"))
    assert [(f["rule_id"], f["path"], f["kind"]) for f in findings] == [
        ("SECRET_IN_EXPOSED_FILE", "/etc/app/app.conf", "password in a URL"),
        ("SECRET_IN_EXPOSED_FILE", "/home/alice/.bash_history", "GitHub token"),
    ]
    assert "a shell history" in findings[1]["detail"] and findings[1]["readable_by"] == "everyone"


def test_command_lines(root):
    cases = {("mysql", "-uroot", "-p" + PASSWORD): ["password given with -p"],
             ("curl", "-u", "me:" + PASSWORD, "https://api.internal"): ["password given with --user"],
             ("deploy", "--token=" + GITHUB): ["value of --token", "GitHub token"],
             ("deploy", "--password", "${DEPLOY_PASSWORD}"): [],
             ("ls", "-p"): []}
    for argv, kinds in cases.items():
        assert [k for k, *_ in sc.command_line_secrets(list(argv))] == kinds, argv
    proc(root, 4242, "/usr/bin/mysql", [], cmdline=b"\0".join([b"mysql", b"-p" + PASSWORD.encode()]))
    findings, gaps = sc.scan_processes(str(root))
    assert [(f["rule_id"], f["subject"], f["program"]) for f in findings] == [
        ("SECRET_IN_COMMAND_LINE", "process:4242", "/usr/bin/mysql")] and gaps == []
    assert PASSWORD not in json.dumps(findings)
    put(root, "/proc/mounts", "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0\n")
    assert sc.scan_processes(str(root)) == ([], [
        "process command lines are hidden from other users (hidepid); they were not checked"])


def test_baseline_check_accept_and_no_value_in_any_report(root, tmp_path):
    manifest = tmp_path / "secrets.json"
    put(root, "/etc/app/app.conf", f"token = {GITHUB}\n")
    first = sc.baseline(manifest, root=str(root), search=("/etc",))
    assert [f["rule_id"] for f in first["findings"]] == ["SECRET_IN_EXPOSED_FILE"], "everything found is reported"
    assert oct(manifest.stat().st_mode & 0o777) == "0o600"
    for text in (json.dumps(first), manifest.read_text()):
        assert GITHUB not in text and AWS not in text and PASSWORD not in text
    assert sc.check(manifest)["findings"] == [] and sc.check(manifest)["still_present"] == 1
    # Lines added above the secret do not make it new.
    put(root, "/etc/app/app.conf", f"# comment\n# another\ntoken = {GITHUB}\n")
    assert sc.check(manifest)["findings"] == []
    put(root, "/home/alice/.aws/credentials", f"aws_access_key_id = {AWS}\n")
    report = sc.check(manifest)
    assert [f["rule_id"] for f in report["findings"]] == ["CREDENTIAL_FILE_EXPOSED"]
    assert AWS not in json.dumps(report)
    assert sc.accept(manifest)["action"] == "accept" and sc.check(manifest)["findings"] == []
    os.chmod(manifest, 0o644)
    with pytest.raises(sc.SecretsError, match="mode-600"):
        sc.check(manifest)


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys, monkeypatch):
    put(root, "/var/www/html/.env", "APP_ENV=production\n")
    findings, gaps = scan(root, search=("/var/www",))
    report = sc.report(findings, gaps, "check")
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=re_.secret_signals(report), protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert [(d["playbook"], [a["action"] for a in d["actions"]]) for d in decisions] == [
        ("secret-exposed", ["notify"])]
    from megalodon.cli import main
    real = sc.scan
    monkeypatch.setattr(sc, "scan", lambda search=sc.SEARCH, **kw: real(str(root), search=("/var/www",)))
    with pytest.raises(SystemExit) as exit_:
        main(["secrets", "scan"])
    assert exit_.value.code == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "SECRET_FILE_IN_WEB_ROOT"
