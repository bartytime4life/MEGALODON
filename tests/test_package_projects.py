"""pip and npm settings in projects and virtual environments, which win over the system's and the account's."""
from __future__ import annotations

import os

from megalodon import package_ecosystems as pe
from megalodon import package_sources as ps
from test_package_ecosystems import found, place
from test_package_sources import armor, keyring, root  # noqa: F401


def sources(state, manager):
    return sorted((s["file"], s["suite"], s["uri"], s["set_in"]) for s in state["sources"].values()
                  if s["manager"] == manager)


def weakened(state):
    return sorted((w["rule"], w["subject"]) for w in state["weakenings"].values())


def venv(root, folder, conf=None):
    place(root, f"{folder}/pyvenv.cfg", "home = /usr/bin\nversion = 3.12.3\n")
    if conf is not None:
        place(root, f"{folder}/pip.conf", conf)


def test_a_virtual_environment_s_own_index_is_recorded_and_its_change_is_a_redirect(root, tmp_path):
    manifest = tmp_path / "packages.json"
    venv(root, "/home/dev/app/.venv")                                  # no pip.conf: the account's settings
    ps.baseline(manifest, root=str(root))
    assert [s for s in sources(ps.snapshot(root=str(root)), "pip") if "virtual" in s[0]] == []
    place(root, "/home/dev/app/.venv/pip.conf", "[global]\nindex-url = https://pypi.corp.example/simple\n")
    report = ps.check(manifest, root=str(root))
    assert found(report) == [("MEDIUM", "PACKAGE_SOURCE_ADDED", "source:pip pip https://pypi.corp.example/simple "
                                                                "pip for virtual environment /home/dev/app/.venv "
                                                                "index-url")]
    ps.accept(manifest, root=str(root))
    place(root, "/home/dev/app/.venv/pip.conf", "[install]\nindex-url = https://pypi.attacker.example/simple\n")
    report = ps.check(manifest, root=str(root))
    assert [f["rule_id"] for f in report["findings"]] == ["PACKAGE_SOURCE_REDIRECTED"]
    assert report["findings"][0]["detail"] == (
        "index-url in pip for virtual environment /home/dev/app/.venv: https://pypi.corp.example/simple → "
        "https://pypi.attacker.example/simple")


def test_a_virtual_environment_records_only_what_its_own_file_sets(root):
    place(root, "/home/dev/.config/pip/pip.conf", "[global]\nindex-url = https://pypi.corp.example/simple\n")
    venv(root, "/home/dev/app/venv", "[global]\nextra-index-url = https://pypi.org/simple\n"
                                     "trusted-host = pypi.corp.example\n")
    state = ps.snapshot(root=str(root))
    assert sources(state, "pip") == [
        ("pip for account dev", "index-url", "https://pypi.corp.example/simple", "/home/dev/.config/pip/pip.conf"),
        ("pip for the system", "index-url", "https://pypi.org/simple", "(default)"),
        ("pip for virtual environment /home/dev/app/venv", "extra-index-url", "https://pypi.org/simple",
         "/home/dev/app/venv/pip.conf")], "the account's index is not repeated for the environment"
    assert weakened(state) == [
        ("PACKAGE_INDEX_MIXED", "pip:virtual environment /home/dev/app/venv:extra-index-url"),
        ("PACKAGE_TRANSPORT_WEAKENED", "pip:virtual environment /home/dev/app/venv:trusted-host:pypi.corp.example")]
    mixed = next(w for w in state["weakenings"].values() if w["rule"] == "PACKAGE_INDEX_MIXED")
    assert "as well as https://pypi.corp.example/simple" in mixed["detail"], "judged with the inherited index"


def test_the_environment_still_wins_over_a_virtual_environment(root):
    place(root, "/etc/environment", "PIP_INDEX_URL=https://mirror.example/simple\n")
    venv(root, "/home/dev/app/.venv", "[global]\nindex-url = https://ignored.example/simple\n")
    state = ps.snapshot(root=str(root))
    assert [s for s in sources(state, "pip") if "virtual" in s[0]] == [], "pip never uses that file's index"


def test_a_virtual_environment_is_read_even_without_a_system_pip(root):
    venv(root, "/opt/service/venv", "[global]\nindex-url = http://pypi.lan.example/simple\n")
    state = ps.snapshot(root=str(root))
    assert ("pip for virtual environment /opt/service/venv", "index-url", "http://pypi.lan.example/simple",
            "/opt/service/venv/pip.conf") in sources(state, "pip")
    assert ("PACKAGE_TRANSPORT_WEAKENED",
            "pip:virtual environment /opt/service/venv:plain:http://pypi.lan.example/simple") in weakened(state)


def test_index_options_in_requirements_files(root):
    place(root, "/srv/api/requirements.txt", "# pinned\n-i https://pypi.corp.example/simple\n"
                                             "--extra-index-url https://pypi.org/simple  # public too\n"
                                             "--trusted-host pypi.corp.example\nflask==3.0.0\n")
    place(root, "/srv/api/requirements-dev.txt", "--index-url=http://pypi.lan.example/simple\n"
                                                 "-f http://wheels.lan.example/\n--index-url ${CORP_INDEX}\n")
    place(root, "/srv/api/notes.txt", "--index-url https://not-requirements.example/simple\n")
    gaps = []
    state = ps.snapshot(root=str(root))
    gaps = state["gaps"]
    assert [s for s in sources(state, "pip") if "requirements" in s[0]] == [
        ("pip for requirements /srv/api/requirements-dev.txt", "find-links", "http://wheels.lan.example/",
         "/srv/api/requirements-dev.txt"),
        ("pip for requirements /srv/api/requirements-dev.txt", "index-url", "http://pypi.lan.example/simple",
         "/srv/api/requirements-dev.txt"),
        ("pip for requirements /srv/api/requirements.txt", "extra-index-url", "https://pypi.org/simple",
         "/srv/api/requirements.txt"),
        ("pip for requirements /srv/api/requirements.txt", "index-url", "https://pypi.corp.example/simple",
         "/srv/api/requirements.txt")]
    assert weakened(state) == [
        ("PACKAGE_INDEX_MIXED", "pip:requirements /srv/api/requirements.txt:extra-index-url"),
        ("PACKAGE_TRANSPORT_WEAKENED",
         "pip:requirements /srv/api/requirements-dev.txt:plain:http://pypi.lan.example/simple"),
        ("PACKAGE_TRANSPORT_WEAKENED", "pip:requirements /srv/api/requirements-dev.txt:plain:http://wheels.lan.example/"),
        ("PACKAGE_TRANSPORT_WEAKENED", "pip:requirements /srv/api/requirements.txt:trusted-host:pypi.corp.example")]
    assert "--index-url in /srv/api/requirements-dev.txt is built from an environment variable: its value is not " \
           "known" in gaps


def test_a_project_s_npmrc_is_read_over_the_account_s(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/home/dev/.npmrc", "registry=https://npm.corp.example/\n")
    ps.baseline(manifest, root=str(root))
    place(root, "/home/dev/web/.npmrc", "@corp:registry=http://npm.lan.example/\nstrict-ssl=false\n"
                                        "//npm.lan.example/:_authToken=${NPM_TOKEN}\n")
    place(root, "/srv/site/.npmrc", "registry=${NPM_REGISTRY}\n")
    report = ps.check(manifest, root=str(root))
    assert found(report) == [
        ("HIGH", "PACKAGE_TRANSPORT_WEAKENED", "npm:project /home/dev/web:plain:http://npm.lan.example/"),
        ("HIGH", "PACKAGE_TRANSPORT_WEAKENED", "npm:project /home/dev/web:strict-ssl"),
        ("MEDIUM", "PACKAGE_SOURCE_ADDED",
         "source:npm npm http://npm.lan.example/ npm for project /home/dev/web @corp:registry")], \
        "the account's registry, inherited, is not repeated for the project"
    assert "registry in /srv/site/.npmrc is built from an environment variable: its value is not known" in \
        report["gaps"]


def test_where_projects_are_looked_for(root, monkeypatch):
    venv(root, "/home/dev/app/.venv", "[global]\nindex-url = https://a.example/simple\n")
    place(root, "/home/dev/app/.venv/lib/requirements.txt", "-i https://inside-venv.example/simple\n")
    place(root, "/home/dev/web/node_modules/pkg/.npmrc", "registry=https://inside-modules.example/\n")
    place(root, "/home/dev/.cache/proj/.npmrc", "registry=https://hidden.example/\n")
    place(root, "/home/dev/" + "/".join(f"d{n}" for n in range(pe.MAX_WALK_DEPTH + 1)) + "/requirements.txt",
          "-i https://too-deep.example/simple\n")
    place(root, "/tmp/elsewhere/requirements.txt", "-i https://elsewhere.example/simple\n")
    place(root, "/var/www/shop/requirements.txt", "-i https://shop.example/simple\n")
    os.symlink(str(root / "tmp/elsewhere"), str(root / "home/dev/link"))
    state = ps.snapshot(root=str(root))
    uris = {s["uri"] for s in state["sources"].values()}
    assert {"https://a.example/simple", "https://shop.example/simple"} <= uris
    assert not uris & {"https://inside-venv.example/simple", "https://inside-modules.example/",
                       "https://hidden.example/", "https://too-deep.example/simple",
                       "https://elsewhere.example/simple"}, "symbolic links, hidden folders and packages are skipped"
    monkeypatch.setattr(pe, "MAX_WALK_FOLDERS", 3)
    gaps = ps.snapshot(root=str(root))["gaps"]
    assert any(g.startswith("more than 3 folders under the homes") for g in gaps)


def test_a_virtual_environment_s_index_wins_over_the_account_s(root):
    place(root, "/home/dev/.pip/pip.conf", "[global]\nindex-url = https://pypi.corp.example/simple\n")
    venv(root, "/home/dev/app/.venv", "[global]\nindex-url = https://pypi.team.example/simple\n")
    assert ("pip for virtual environment /home/dev/app/.venv", "index-url", "https://pypi.team.example/simple",
            "/home/dev/app/.venv/pip.conf") in sources(ps.snapshot(root=str(root)), "pip")


def test_the_last_index_in_a_requirements_file_wins(root):
    place(root, "/srv/api/requirements.txt", "-i https://first.example/simple\n-i https://last.example/simple\n")
    assert [s[2] for s in sources(ps.snapshot(root=str(root)), "pip") if "requirements" in s[0]] == [
        "https://last.example/simple"]


def test_a_home_s_own_npmrc_is_the_account_s_and_projects_need_no_npm_installed(root):
    place(root, "/home/dev/.npmrc", "registry=https://npm.corp.example/\n")
    place(root, "/opt/tool/.npmrc", "registry=https://npm.tool.example/\n")
    labels = {s[0] for s in sources(ps.snapshot(root=str(root)), "npm")}
    assert labels == {"npm for the system", "npm for account dev", "npm for project /opt/tool"}
    os.unlink(root / "home/dev/.npmrc")                                 # nothing else says npm is here
    assert "npm for project /opt/tool" in {s[0] for s in sources(ps.snapshot(root=str(root)), "npm")}
