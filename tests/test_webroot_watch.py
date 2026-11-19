"""Web-root watch: dropped scripts, hidden code and web-shell shapes in a constructed document root."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from megalodon import response_engine as re_
from megalodon import webroot_watch as ww

# Minimal, inert examples of the shapes the watch looks for. None of them is a working tool.
SHELL_CALL = '<?php system($_GET["c"]); ?>\n'
OBFUSCATED = '<?php eval(gzinflate(base64_decode("AAAA"))); ?>\n'
JSP_CALL = '<% Runtime.getRuntime().exec(request.getParameter("c")); %>\n'


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "www"
    (root / "html/wp-content/uploads/2026").mkdir(parents=True)
    (root / "html/index.php").write_text("<?php require 'wp-blog-header.php'; ?>\n")
    (root / "html/wp-blog-header.php").write_text("<?php // loads the site\n")
    (root / "html/style.css").write_text("body { color: #333; }\n")
    (root / "html/wp-content/uploads/2026/photo.jpg").write_bytes(b"\xff\xd8\xff\xe0JFIF" + b"\0" * 64)
    (root / "html/node_modules/x").mkdir(parents=True)
    (root / "html/node_modules/x/shell.php").write_text(SHELL_CALL)    # skipped folder
    return root


def rules(report):
    return sorted((f["rule_id"], Path(f["path"]).name) for f in report["findings"])


def test_dropped_scripts_hidden_code_and_web_shell_shapes(site, tmp_path):
    manifest = tmp_path / "webroot.json"
    result = ww.baseline(manifest, web_roots=[str(site)])
    assert result["files"] == 2 and result["findings"] == [] and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert ww.check(manifest)["findings"] == []
    html = site / "html"
    (html / "wp-content/uploads/2026/cache.php").write_text(SHELL_CALL)          # dropped into uploads
    (html / "wp-content/uploads/2026/logo.png").write_bytes(b"\x89PNG\r\n" + OBFUSCATED.encode())   # polyglot
    (html / "about.php").write_text("<?php echo 'about'; ?>\n")                  # an ordinary new page
    with open(html / "index.php", "a") as page:                                    # an injected backdoor
        page.write(OBFUSCATED)
    report = ww.check(manifest)
    assert rules(report) == [
        ("CODE_IN_NON_SCRIPT_FILE", "logo.png"), ("SCRIPT_IN_UPLOAD_FOLDER", "cache.php"),
        ("WEB_SCRIPT_ADDED", "about.php"), ("WEB_SCRIPT_CHANGED", "index.php"),
        ("WEB_SHELL_PATTERN", "cache.php"), ("WEB_SHELL_PATTERN", "index.php"), ("WEB_SHELL_PATTERN", "logo.png")]
    assert report["findings"][0]["severity"] == "CRITICAL" and report["findings"][0]["techniques"] == ["T1505.003"]
    patterns = {Path(f["path"]).name: f["detail"] for f in report["findings"] if f["rule_id"] == "WEB_SHELL_PATTERN"}
    assert "request input" in patterns["cache.php"] and "decoded" in patterns["logo.png"]


def test_a_web_shell_already_present_is_reported_at_baseline(site, tmp_path):
    (site / "html/legacy.jsp").write_text(JSP_CALL)
    result = ww.baseline(tmp_path / "webroot.json", web_roots=[str(site)])
    assert [(f["rule_id"], Path(f["path"]).name) for f in result["findings"]] == [("WEB_SHELL_PATTERN", "legacy.jsp")]


def test_ordinary_code_stays_quiet(site, tmp_path):
    html = site / "html"
    (html / "lib.php").write_text("<?php\n$query = $_GET['q'];\necho htmlspecialchars($query);\n"
                                  "$data = base64_decode($stored);\nexec_query($db, $sql);\n")
    report = ww.baseline(tmp_path / "webroot.json", web_roots=[str(site)])
    assert report["findings"] == []


def test_accept_and_large_files(site, tmp_path, monkeypatch):
    manifest = tmp_path / "webroot.json"
    monkeypatch.setattr(ww, "MAX_HASH", 16)
    (site / "html/big.php").write_text("<?php // " + "x" * 100 + "\n")
    ww.baseline(manifest, web_roots=[str(site)])
    assert ww.check(manifest)["findings"] == [], "an unhashed file is compared by size and time, not re-reported"
    (site / "html/new.php").write_text("<?php\n")
    assert rules(ww.check(manifest)) == [("WEB_SCRIPT_ADDED", "new.php")]
    ww.accept(manifest)
    assert ww.check(manifest)["findings"] == []
    with pytest.raises(ww.WebrootError, match="use accept"):
        ww.baseline(manifest, web_roots=[str(site)])
    os.chmod(manifest, 0o644)
    with pytest.raises(ww.WebrootError, match="mode-600"):
        ww.check(manifest)


def test_no_web_root_is_a_gap(tmp_path):
    report = ww.baseline(tmp_path / "webroot.json", web_roots=[str(tmp_path / "absent")])
    assert report["files"] == 0 and "no web root" in report["gaps"][0]


def test_findings_reach_the_response_engine(site, tmp_path):
    manifest = tmp_path / "webroot.json"
    ww.baseline(manifest, web_roots=[str(site)])
    (site / "html/wp-content/uploads/2026/x.php").write_text(SHELL_CALL)
    signals = re_.path_signals(ww.check(manifest), "webroot", "path")
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert {d["playbook"] for d in decisions} == {"web-shell-file"}
    target = str(site / "html/wp-content/uploads/2026/x.php")
    assert any(a["action"] == "quarantine_file" and a["target"] == target for d in decisions for a in d["actions"])


def test_cli(site, tmp_path, capsys):
    from megalodon.cli import main
    manifest = tmp_path / "webroot.json"

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("webroot", "baseline", "--manifest", str(manifest), "--root", str(site)) == 0
    assert code("webroot", "check", "--manifest", str(manifest)) == 0
    (site / "html/x.php").write_text(SHELL_CALL)
    capsys.readouterr()
    assert code("webroot", "check", "--manifest", str(manifest)) == 1
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]} == {
        "WEB_SCRIPT_ADDED", "WEB_SHELL_PATTERN"}
