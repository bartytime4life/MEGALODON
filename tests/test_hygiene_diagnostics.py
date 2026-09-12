"""Inert filename diagnostics; no operator files or runner commands executed."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools import check_repository_hygiene as guard


NAMES = (
    "ordinary.pem",
    "line\nsecond.pem",
    "return\rsecond.pem",
    "tab\tname.pem",
    "escape\x1b[2J.pem",
    "osc\x1b]0;synthetic\x07.pem",
    "delete\x7f.pem",
    "next-line\x85.pem",
    "separator\u2028.pem",
    "bidi\u202e.pem",
    "unicode-\u00e9-\U0001f642.pem",
    "embedded::notice::INERT.pem",
    "legacy##[warning]INERT.pem",
    "line\n::notice::INERT.pem",
)


def assert_safe_display(value):
    assert all(0x20 <= ord(char) < 0x7f for char in value)
    # Protect modern and legacy runner command delimiters, including mid-line.
    assert "::" not in value
    assert "##[" not in value


@pytest.mark.parametrize("name", NAMES)
def test_display_is_single_line_ascii_and_reversible(name):
    rendered = guard._display_path(name)
    assert_safe_display(rendered)
    assert json.loads('"' + rendered + '"') == name


def test_all_byte_characters_and_unicode_extremes_are_escaped():
    for code in (*range(256), 0x2028, 0x2029, 0x202e, 0x2066, 0xd800, 0xdcff, 0x10ffff):
        name = chr(code)
        rendered = guard._display_path(name)
        assert_safe_display(rendered)
        assert json.loads('"' + rendered + '"') == name


@pytest.mark.parametrize("unit", ("a", "\n", ":", "#", "\\", "\u202e", "\U0001f642"))
def test_display_budget_stops_before_encoding_the_unbounded_suffix(monkeypatch, unit):
    name = unit * 100_000
    calls = 0
    original = guard.json.dumps

    def counted(value, **kwargs):
        nonlocal calls
        calls += 1
        assert len(value) == 1
        return original(value, **kwargs)

    monkeypatch.setattr(guard.json, "dumps", counted)
    rendered = guard._display_path(name)
    assert calls <= guard.MAX_DISPLAY_PATH_CHARS + 1
    assert len(rendered) <= guard.MAX_DISPLAY_PATH_CHARS
    assert rendered.endswith("...[truncated]")
    assert_safe_display(rendered)
    # The prefix ends at an escape boundary, not halfway through a code point.
    prefix = rendered.removesuffix("...[truncated]")
    assert name.startswith(json.loads('"' + prefix + '"'))


def test_display_exact_prefix_budget_and_overflow():
    budget = guard.MAX_DISPLAY_PATH_CHARS - len("...[truncated]")
    assert guard._display_path("a" * budget) == "a" * budget
    assert guard._display_path("a" * (budget + 1)) == "a" * budget + "...[truncated]"


@pytest.mark.skipif(os.name != "posix", reason="POSIX hostile filename fixture")
@pytest.mark.parametrize("name", NAMES)
def test_main_keeps_one_line_per_finding_and_nonzero_status(tmp_path, monkeypatch, capsys, name):
    (tmp_path / name).write_text("synthetic ordinary text", encoding="utf-8")
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "tracked_paths", lambda: (name,))
    assert guard.main() == 1
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 2
    assert lines[0] == "repository hygiene guard: failed"
    assert lines[1].startswith("- sensitive tracked filename: ")
    assert_safe_display(lines[1])
    assert "synthetic ordinary text" not in output.out


@pytest.mark.skipif(os.name != "posix", reason="POSIX hostile filename fixture")
@pytest.mark.parametrize("kind", ("directory", "unreadable", "changed", "large-and-secret"))
def test_every_finding_family_uses_safe_filename(tmp_path, monkeypatch, kind):
    name = "test\n::notice::INERT\u202e.pem"
    path = tmp_path / name
    if kind == "directory":
        path.mkdir()
        expected = ["tracked path is not a regular file"]
    else:
        # Marker shapes are composed only in temporary synthetic content.
        path.write_bytes(b"\0\n" + b"-----BEGIN " + b"PRIVATE KEY-----\n"
                         + b"AKIA" + b"0123456789ABCDEF\n"
                         + b"ghp_" + b"A" * 20 + b"\n"
                         + b"xoxb-" + b"B" * 20)
        if kind in ("unreadable", "changed"):
            def refuse(*args):
                error = guard._ChangedFileError if kind == "changed" else OSError
                raise error("PRIVATE_EXCEPTION_MUST_NOT_APPEAR")

            monkeypatch.setattr(guard, "_read_checked", refuse)
            expected = ["tracked file changed during scan" if kind == "changed"
                        else "tracked file is unreadable"]
        else:
            expected = ["large tracked file", "large tracked binary",
                        "suspected private-key marker", "suspected aws-access-key marker",
                        "suspected github-token marker", "suspected slack-token marker"]
    findings = guard.scan_paths(tmp_path, (name,), max_file_bytes=100, max_binary_bytes=1)
    assert len(findings) == 1 + len(expected)
    for label in ("sensitive tracked filename", *expected):
        finding = next(item for item in findings if item.startswith(label + ": "))
        assert_safe_display(finding)
        assert "PRIVATE_EXCEPTION_MUST_NOT_APPEAR" not in finding
        assert "synthetic ordinary text" not in finding


@pytest.mark.skipif(os.name != "posix", reason="POSIX backslash filename fixture")
def test_display_does_not_confuse_backslash_filename_with_directory(tmp_path):
    (tmp_path / "part").mkdir()
    (tmp_path / "part" / "key.pem").write_text("synthetic", encoding="ascii")
    (tmp_path / "part\\key.pem").write_text("synthetic", encoding="ascii")
    findings = guard.scan_paths(tmp_path, ("part/key.pem", "part\\key.pem"))
    assert findings == ["sensitive tracked filename: part/key.pem",
                        r"sensitive tracked filename: part\\key.pem"]


def test_truncated_display_does_not_shorten_the_actual_read_path(tmp_path):
    directory = tmp_path
    for _ in range(4):
        directory = directory / ("a" * 70)
        directory.mkdir()
    path = directory / "fixture.txt"
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    path.write_text(marker, encoding="ascii")
    relative = path.relative_to(tmp_path).as_posix()
    findings = guard.scan_paths(tmp_path, (relative,))
    assert len(findings) == 1
    assert findings[0].startswith("suspected private-key marker: ")
    assert findings[0].endswith("...[truncated]")
    assert marker not in findings[0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX Git filename fixture")
def test_real_git_and_bounded_child_keep_hostile_names_as_data(tmp_path):
    name = "fixture\n::notice::INERT.pem"
    (tmp_path / name).write_text("synthetic ordinary text", encoding="ascii")
    for args in (("git", "-c", "init.templateDir=", "init", "-q"),
                 ("git", "add", "--", name)):
        subprocess.run(args, cwd=tmp_path, check=True, capture_output=True, timeout=5)
    script = r'''
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("guard", sys.argv[1])
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
root = Path(sys.argv[2])
paths = guard.tracked_paths(root)
assert len(paths) == 1 and "\n" in paths[0]
guard.ROOT = root
guard.tracked_paths = lambda: paths
raise SystemExit(guard.main())
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(Path(guard.__file__).resolve()), str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 1
    assert result.stderr == ""
    assert len(result.stdout.splitlines()) == 2
    assert_safe_display(result.stdout.removesuffix("\n").replace("\n", ""))
    assert "synthetic ordinary text" not in result.stdout


def test_error_receipt_remains_path_free(monkeypatch, capsys):
    def refuse():
        raise RuntimeError("PRIVATE_EXCEPTION\n::notice::INERT")

    monkeypatch.setattr(guard, "tracked_paths", refuse)
    assert guard.main() == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "repository hygiene guard error: RuntimeError\n"
