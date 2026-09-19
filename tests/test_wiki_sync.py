"""Offline ownership and publication tests for generated GitHub Wiki pages."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sync_wiki_pages", ROOT / "tools/sync_wiki_pages.py")
wiki = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wiki)


@pytest.fixture
def directories(tmp_path):
    source, checkout = tmp_path / "generated", tmp_path / "checkout"
    source.mkdir()
    checkout.mkdir()
    (source / "Home.md").write_text("# Home\n")
    return source, checkout


def snapshot(directory):
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.is_symlink()}


def test_first_adoption_preserves_unmanaged_pages_and_records_exact_bytes(directories):
    source, checkout = directories
    (source / "_Sidebar.md").write_text("* [Home](Home)\n")
    (checkout / "Home.md").write_text("Older generated home\n")
    (checkout / "old-legacy-page.md").write_text("No ownership evidence\n")
    (checkout / "Manual.md").write_text("Maintainer page\n")
    wiki.synchronize(source, checkout)
    assert (checkout / "Home.md").read_bytes() == (source / "Home.md").read_bytes()
    assert (checkout / "old-legacy-page.md").read_text() == "No ownership evidence\n"
    assert (checkout / "Manual.md").read_text() == "Maintainer page\n"
    manifest = json.loads((checkout / wiki.MANIFEST).read_bytes())
    assert manifest == {"schema": wiki.SCHEMA, "pages": {
        name: hashlib.sha256(data).hexdigest() for name, data in snapshot(source).items()
    }}


def test_removal_and_rename_prune_only_unchanged_owned_pages(directories):
    source, checkout = directories
    (source / "old-name.md").write_text("# Keep this content\n")
    (source / "removed.md").write_text("# Remove\n")
    wiki.synchronize(source, checkout)
    (checkout / "Manual.md").write_text("Keep me\n")
    (source / "old-name.md").rename(source / "new-name.md")
    (source / "removed.md").unlink()
    wiki.synchronize(source, checkout)
    assert not (checkout / "old-name.md").exists()
    assert not (checkout / "removed.md").exists()
    assert (checkout / "new-name.md").read_text() == "# Keep this content\n"
    assert (checkout / "Manual.md").read_text() == "Keep me\n"
    assert set(json.loads((checkout / wiki.MANIFEST).read_bytes())["pages"]) == {"Home.md", "new-name.md"}


def test_idempotence_preserves_bytes_and_file_modification_times(directories):
    source, checkout = directories
    wiki.synchronize(source, checkout)
    before = snapshot(checkout)
    times = {p.name: p.stat().st_mtime_ns for p in checkout.iterdir()}
    wiki.synchronize(source, checkout)
    assert snapshot(checkout) == before
    assert {p.name: p.stat().st_mtime_ns for p in checkout.iterdir()} == times


def test_already_missing_owned_page_is_reconciled(directories):
    source, checkout = directories
    (source / "removed.md").write_text("")
    wiki.synchronize(source, checkout)
    (source / "removed.md").unlink()
    (checkout / "removed.md").unlink()
    wiki.synchronize(source, checkout)
    assert set(json.loads((checkout / wiki.MANIFEST).read_bytes())["pages"]) == {"Home.md"}


def test_edited_obsolete_page_refuses_before_any_page_or_manifest_change(directories):
    source, checkout = directories
    (source / "old.md").write_text("Generated\n")
    wiki.synchronize(source, checkout)
    (source / "old.md").unlink()
    (source / "Home.md").write_text("New home\n")
    (checkout / "old.md").write_text("Manual edits worth preserving\n")
    before = snapshot(checkout)
    with pytest.raises(wiki.WikiSyncError, match="obsolete.*edited"):
        wiki.synchronize(source, checkout)
    assert snapshot(checkout) == before


@pytest.mark.parametrize("raw", [
    b"not json", b"[]", b"\xff", b"9" * 5000, b'{"schema":"wrong","pages":{}}',
    b'{"schema":"megalodon-wiki-pages-v1","pages":{},"extra":true}',
    b'{"schema":"megalodon-wiki-pages-v1","pages":{},"pages":{}}',
    json.dumps({"schema": wiki.SCHEMA, "pages": {"Home.md": "not-a-digest"}}).encode(),
    json.dumps({"schema": wiki.SCHEMA, "pages": {"../escape.md": "0" * 64}}).encode(),
    json.dumps({"schema": wiki.SCHEMA, "pages": {"/outside.md": "0" * 64}}).encode(),
    json.dumps({"schema": wiki.SCHEMA, "pages": {"..\\escape.md": "0" * 64}}).encode(),
])
def test_malformed_manifest_refuses_before_changes(directories, raw):
    source, checkout = directories
    (checkout / wiki.MANIFEST).write_bytes(raw)
    before = snapshot(checkout)
    with pytest.raises(wiki.WikiSyncError):
        wiki.synchronize(source, checkout)
    assert snapshot(checkout) == before


@pytest.mark.parametrize("name", [".hidden.md", "two words.md", "bad.html", "nested"])
def test_unsupported_generated_names_refuse_before_changes(directories, name):
    source, checkout = directories
    (source / name).write_text("Invalid generated page")
    with pytest.raises(wiki.WikiSyncError):
        wiki.synchronize(source, checkout)
    assert list(checkout.iterdir()) == []


@pytest.mark.parametrize("location", ["source", "destination", "manifest", "obsolete", "directory"])
def test_symlinks_are_refused_before_changes(directories, tmp_path, location):
    source, checkout = directories
    external = tmp_path / "external.md"
    external.write_text("Untouched external content\n")
    if location == "obsolete":
        (source / "old.md").write_text("Generated\n")
        wiki.synchronize(source, checkout)
        (source / "old.md").unlink()
        (checkout / "old.md").unlink()
        link = checkout / "old.md"
    else:
        link = {"source": source / "Home.md", "destination": checkout / "Home.md",
                "manifest": checkout / wiki.MANIFEST, "directory": tmp_path / "linked"}[location]
        link.unlink(missing_ok=True)
    try:
        link.symlink_to(source if location == "directory" else external)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")
    before = snapshot(checkout)
    with pytest.raises(wiki.WikiSyncError):
        wiki.synchronize(link if location == "directory" else source, checkout)
    assert snapshot(checkout) == before
    assert link.is_symlink()
    assert external.read_text() == "Untouched external content\n"


def test_nonregular_destination_refuses_before_other_updates(directories):
    source, checkout = directories
    (source / "Home.md").write_text("New home\n")
    (source / "later.md").write_text("Page\n")
    (checkout / "Home.md").write_text("Original\n")
    (checkout / "later.md").mkdir()
    with pytest.raises(wiki.WikiSyncError):
        wiki.synchronize(source, checkout)
    assert (checkout / "Home.md").read_text() == "Original\n"
    assert not (checkout / wiki.MANIFEST).exists()


def test_replacing_current_pages_does_not_edit_hardlinked_manual_pages(directories):
    source, checkout = directories
    (checkout / "Manual.md").write_text("Keep manual content\n")
    os.link(checkout / "Manual.md", checkout / "Home.md")
    wiki.synchronize(source, checkout)
    assert (checkout / "Manual.md").read_text() == "Keep manual content\n"
    assert (checkout / "Home.md").read_bytes() == (source / "Home.md").read_bytes()


@pytest.mark.skipif(sys.platform != "linux", reason="Wiki validation shell runs on Linux")
@pytest.mark.parametrize("page_name, expected_returncode", [("operator-guide.md", 0), ("two words.md", 1)])
def test_validate_shell_exercises_helper_without_git_or_network(tmp_path, page_name, expected_returncode):
    project, bin_dir, runtime = [tmp_path / name for name in ("project", "bin", "runtime")]
    for directory in (project, bin_dir, runtime):
        directory.mkdir()
    (project / "docs/wiki").mkdir(parents=True)
    for relative in (".github/scripts/sync-wiki.sh", "tools/sync_wiki_pages.py"):
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    (project / "docs/wiki/README.md").write_text("# MEGALODON Documentation Wiki\n")
    (project / "docs/wiki" / page_name).write_text("# Operator guide\n")
    tripwire = tmp_path / "unexpected-external-command"
    for command in ("git", "curl"):
        executable = bin_dir / command
        executable.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                              f"Path({str(tripwire)!r}).write_text('called')\nraise SystemExit(99)\n")
        executable.chmod(0o755)
    env = {key: value for key, value in os.environ.items() if key != "GH_TOKEN"}
    env.update({"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(runtime)})
    result = subprocess.run(["bash", ".github/scripts/sync-wiki.sh", "--validate"], cwd=project,
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == expected_returncode, result.stderr
    if expected_returncode:
        assert "supported Markdown page names" in result.stderr
    assert not tripwire.exists()
    assert list(runtime.iterdir()) == []


@pytest.mark.skipif(sys.platform != "linux", reason="Wiki publication shell runs on Linux")
@pytest.mark.parametrize("edited_obsolete", [False, True])
def test_publish_shell_prunes_in_local_git_without_network(tmp_path, edited_obsolete):
    git = shutil.which("git")
    assert git is not None, "Git is required for the offline Wiki publication test"
    project, bin_dir, runtime, remote = [tmp_path / name for name in ("project", "bin", "runtime", "wiki.git")]
    for directory in (project, bin_dir, runtime):
        directory.mkdir()
    (project / "docs/wiki").mkdir(parents=True)
    for relative in (".github/scripts/sync-wiki.sh", "tools/sync_wiki_pages.py"):
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    (project / "docs/wiki/README.md").write_text("# MEGALODON Documentation Wiki\n")
    (project / "docs/wiki/old.md").write_text("# Older page\n")
    subprocess.run([git, "init", "--bare", "--initial-branch=master", str(remote)], check=True, capture_output=True)
    wrappers = {
        "git": '''import os, sys
args = sys.argv[1:]
if args[0] == "clone":
    args[1] = os.environ["WIKI_TEST_REMOTE"]
os.execv(os.environ["WIKI_TEST_GIT"], [os.environ["WIKI_TEST_GIT"], *args])
''',
        "curl": '''from pathlib import Path
import sys
Path(sys.argv[sys.argv.index("--output") + 1]).write_text("MEGALODON Documentation Wiki")
print("200", end="")
''',
    }
    for name, body in wrappers.items():
        path = bin_dir / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "RUNNER_TEMP": str(runtime), "GH_TOKEN": "offline-synthetic-token",
           "GITHUB_REPOSITORY": "fixture/repository", "GITHUB_SHA": "0" * 40,
           "WIKI_TEST_REMOTE": str(remote), "WIKI_TEST_GIT": git,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0"}
    def publish(expected_returncode=0):
        result = subprocess.run(["bash", ".github/scripts/sync-wiki.sh", "--publish"],
                                cwd=project, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == expected_returncode, result.stderr
        return result.stdout + result.stderr
    publish()
    (project / "docs/wiki/old.md").rename(project / "docs/wiki/new.md")
    if edited_obsolete:
        manual = tmp_path / "manual-edit"
        subprocess.run([git, "clone", str(remote), str(manual)], check=True, capture_output=True, env=env)
        (manual / "old.md").write_text("Manual edits to preserve\n")
        for arguments in (["add", "old.md"], ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                             "commit", "-m", "manual edit"], ["push", "origin", "HEAD:master"]):
            subprocess.run([git, "-C", str(manual), *arguments], check=True, capture_output=True, env=env)
        before = subprocess.run([git, "--git-dir", str(remote), "rev-parse", "HEAD"],
                                check=True, capture_output=True, text=True).stdout
        assert "obsolete generated Wiki page was edited" in publish(expected_returncode=1)
        after = subprocess.run([git, "--git-dir", str(remote), "rev-parse", "HEAD"],
                               check=True, capture_output=True, text=True).stdout
        assert after == before
        return
    publish()
    listed = subprocess.run([git, "--git-dir", str(remote), "ls-tree", "--name-only", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.splitlines()
    assert set(listed) == {"Home.md", "new.md", "_Sidebar.md", "_Footer.md", wiki.MANIFEST}
    before = subprocess.run([git, "--git-dir", str(remote), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout
    assert "Wiki is already current." in publish()
    after = subprocess.run([git, "--git-dir", str(remote), "rev-parse", "HEAD"],
                           check=True, capture_output=True, text=True).stdout
    assert after == before
