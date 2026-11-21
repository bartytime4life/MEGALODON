"""Package indexes named in pyproject.toml and Pipfile, and the hosts npm and yarn lockfiles download from."""
from __future__ import annotations

import json

from megalodon import package_sources as ps
from test_package_ecosystems import found, place
from test_package_sources import armor, keyring, root  # noqa: F401


def sources(state, label_part):
    return sorted((s["file"], s["suite"], s["uri"]) for s in state["sources"].values() if label_part in s["file"])


def weakened(state):
    return sorted((w["rule"], w["subject"], w["severity"]) for w in state["weakenings"].values())


def lock(packages, version=3):
    return json.dumps({"name": "web", "lockfileVersion": version, "packages": {
        "": {"name": "web"}, **{f"node_modules/{name}": {"version": "1.0.0", "resolved": url}
                                for name, url in packages.items()}}})


# ------------------------------------------------------------------ Python projects

def test_poetry_uv_and_pdm_sources_are_recorded(root):
    place(root, "/srv/api/pyproject.toml", """
[tool.poetry]
name = "api"
[[tool.poetry.source]]
name = "corp"
url = "https://pypi.corp.example/simple"
priority = "primary"

[tool.uv]
index-url = "https://uv.corp.example/simple"
allow-insecure-host = ["uv.corp.example"]
[[tool.uv.index]]
name = "lan"
url = "http://pypi.lan.example/simple"

[[tool.pdm.source]]
name = "mirror"
url = "https://pdm.mirror.example/simple"
verify_ssl = false
""")
    state = ps.snapshot(root=str(root))
    assert sources(state, "/srv/api/pyproject.toml") == [
        ("pdm for /srv/api/pyproject.toml", "source mirror", "https://pdm.mirror.example/simple"),
        ("poetry for /srv/api/pyproject.toml", "source corp", "https://pypi.corp.example/simple"),
        ("uv for /srv/api/pyproject.toml", "index lan", "http://pypi.lan.example/simple"),
        ("uv for /srv/api/pyproject.toml", "index-url", "https://uv.corp.example/simple")]
    assert weakened(state) == [
        ("PACKAGE_INDEX_MIXED", "pdm:/srv/api/pyproject.toml:sources", "MEDIUM"),
        ("PACKAGE_TRANSPORT_WEAKENED", "pdm:/srv/api/pyproject.toml:verify_ssl:https://pdm.mirror.example/simple",
         "HIGH"),
        ("PACKAGE_TRANSPORT_WEAKENED", "uv:/srv/api/pyproject.toml:allow-insecure-host:uv.corp.example", "HIGH"),
        ("PACKAGE_TRANSPORT_WEAKENED", "uv:/srv/api/pyproject.toml:plain:http://pypi.lan.example/simple", "HIGH")], \
        "uv takes each package from the first index that has it by default: not mixed"


def test_mixing_is_reported_only_when_the_tool_compares_versions_across_indexes(root):
    place(root, "/srv/a/pyproject.toml", '[tool.uv]\nindex-strategy = "unsafe-best-match"\n'
                                         'extra-index-url = ["https://pypi.corp.example/simple"]\n')
    place(root, "/srv/b/pyproject.toml", '[[tool.pdm.source]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n'
                                         '[tool.pdm.resolution]\nrespect-source-order = true\n')
    place(root, "/srv/c/pyproject.toml", '[[tool.pdm.source]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n'
                                         'include_packages = ["corp-*"]\n')
    assert [w[1] for w in weakened(ps.snapshot(root=str(root)))] == ["uv:/srv/a/pyproject.toml:unsafe-best-match"]


def test_pipfile_sources_and_their_certificate_checks(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/home/dev/app/Pipfile", '[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n'
                                         'verify_ssl = true\n\n[packages]\nrequests = "*"\n')
    ps.baseline(manifest, root=str(root))
    place(root, "/home/dev/app/Pipfile", '[[source]]\nname = "pypi"\nurl = "https://pypi.attacker.example/simple"\n'
                                         'verify_ssl = false\n')
    report = ps.check(manifest, root=str(root))
    assert sorted((f["severity"], f["rule_id"]) for f in report["findings"]) == [
        ("HIGH", "PACKAGE_SOURCE_REDIRECTED"), ("HIGH", "PACKAGE_TRANSPORT_WEAKENED")]
    redirect = next(f for f in report["findings"] if f["rule_id"] == "PACKAGE_SOURCE_REDIRECTED")
    assert redirect["detail"] == ("source pypi in pipenv for /home/dev/app/Pipfile: "
                                               "https://pypi.org/simple → https://pypi.attacker.example/simple")


def test_python_files_that_cannot_be_read_or_name_a_variable_are_gaps(root):
    place(root, "/srv/x/pyproject.toml", "[tool.poetry\nname = 'broken'\n")
    place(root, "/srv/y/Pipfile", '[[source]]\nname = "corp"\nurl = "https://${CORP_USER}@pypi.corp.example/simple"\n')
    state = ps.snapshot(root=str(root))
    assert any(g.startswith("/srv/x/pyproject.toml is not valid TOML") for g in state["gaps"])
    assert "source corp in /srv/y/Pipfile is built from an environment variable: its value is not known" in state["gaps"]
    assert sources(state, "/srv/y/Pipfile") == []


# ------------------------------------------------------------------ lockfiles

def test_a_lockfile_host_no_registry_names_is_reported(root):
    place(root, "/srv/web/package-lock.json", lock({
        "left-pad": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "util": "https://registry.npmjs.org/util/-/util-1.0.0.tgz",
        "corp-ui": "https://npm.attacker.example/corp-ui/-/corp-ui-1.0.0.tgz",
        "fetcher": "http://files.lan.example/fetcher-1.0.0.tgz",
        "from-git": "git+ssh://git@github.com/corp/from-git.git#0123abc"}))
    state = ps.snapshot(root=str(root))
    assert sources(state, "lockfile") == [
        ("npm lockfile /srv/web/package-lock.json", "resolved", "http://files.lan.example/"),
        ("npm lockfile /srv/web/package-lock.json", "resolved", "https://npm.attacker.example/"),
        ("npm lockfile /srv/web/package-lock.json", "resolved", "https://registry.npmjs.org/")]
    assert weakened(state) == [
        ("PACKAGE_LOCKFILE_FOREIGN_HOST", "npm:lockfile /srv/web/package-lock.json:files.lan.example", "MEDIUM"),
        ("PACKAGE_LOCKFILE_FOREIGN_HOST", "npm:lockfile /srv/web/package-lock.json:npm.attacker.example", "MEDIUM"),
        ("PACKAGE_TRANSPORT_WEAKENED", "npm:lockfile /srv/web/package-lock.json:plain:files.lan.example", "HIGH")]
    detail = next(w["detail"] for w in state["weakenings"].values() if "npm.attacker.example" in w["subject"])
    assert detail == ("npm lockfile /srv/web/package-lock.json downloads 1 package from https://npm.attacker.example/, "
                      "which none of the project's registries (https://registry.npmjs.org/) names: npm ci fetches "
                      "them as written")


def test_a_lockfile_is_judged_by_its_own_project_s_registries(root):
    place(root, "/home/dev/.npmrc", "registry=https://npm.corp.example/\n")
    place(root, "/home/dev/web/.npmrc", "@team:registry=https://npm.team.example/\n")
    place(root, "/home/dev/web/package-lock.json", lock({
        "a": "https://npm.corp.example/a/-/a-1.0.0.tgz", "b": "https://npm.team.example/b/-/b-1.0.0.tgz"}))
    place(root, "/srv/other/package-lock.json", lock({"b": "https://npm.team.example/b/-/b-1.0.0.tgz"}, version=1)
          .replace('"packages"', '"dependencies"'))
    found_hosts = [w[1] for w in weakened(ps.snapshot(root=str(root)))]
    assert found_hosts == ["npm:lockfile /srv/other/package-lock.json:npm.team.example"], \
        "the account's and the project's registries count for that project only"


def test_lockfile_versions_and_yarn(root):
    v1 = {"name": "web", "lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
              "dependencies": {"b": {"version": "1.0.0", "resolved": "https://deep.example/b-1.0.0.tgz"}}}}}
    place(root, "/srv/v1/npm-shrinkwrap.json", json.dumps(v1))
    place(root, "/srv/y/yarn.lock", '# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n'
                                    '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"\n'
                                    'odd@^1.0.0:\n  resolved "https://yarn.attacker.example/odd-1.0.0.tgz#def"\n')
    place(root, "/srv/berry/yarn.lock", '__metadata:\n  version: 8\n\n"tool@https://berry.example/tool.tgz":\n'
                                        '  resolution: "tool@https://berry.example/tool.tgz"\n')
    place(root, "/srv/bad/package-lock.json", "{not json")
    state = ps.snapshot(root=str(root))
    assert [w[1] for w in weakened(state)] == [
        "npm:lockfile /srv/berry/yarn.lock:berry.example", "npm:lockfile /srv/v1/npm-shrinkwrap.json:deep.example",
        "npm:lockfile /srv/y/yarn.lock:yarn.attacker.example"], "nested version 1 dependencies are followed"
    assert "/srv/bad/package-lock.json is not valid JSON" in state["gaps"]


def test_a_new_lockfile_host_is_an_added_source_and_reported_at_once(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/srv/web/package-lock.json", lock({"a": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}))
    first = ps.baseline(manifest, root=str(root))
    assert first["findings"] == []
    place(root, "/srv/web/package-lock.json", lock({"a": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                                                     "b": "https://npm.attacker.example/b-1.0.0.tgz"}))
    assert found(ps.check(manifest, root=str(root))) == [
        ("MEDIUM", "PACKAGE_LOCKFILE_FOREIGN_HOST", "npm:lockfile /srv/web/package-lock.json:npm.attacker.example"),
        ("MEDIUM", "PACKAGE_SOURCE_ADDED",
         "source:npm npm https://npm.attacker.example/ npm lockfile /srv/web/package-lock.json resolved")]


def test_nothing_inside_node_modules_is_read(root):
    place(root, "/srv/web/node_modules/dep/package-lock.json", lock({"x": "https://inner.example/x.tgz"}))
    place(root, "/srv/web/node_modules/dep/pyproject.toml", '[tool.uv]\nindex-url = "https://inner.example/simple"\n')
    assert not [s for s in ps.snapshot(root=str(root))["sources"].values() if "inner.example" in s["uri"]]
