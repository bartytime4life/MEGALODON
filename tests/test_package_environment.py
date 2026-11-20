"""pip and npm settings given by environment variables, in the system's and each account's login files."""
from __future__ import annotations

from megalodon import package_sources as ps
from test_package_ecosystems import found, place
from test_package_sources import armor, keyring, root  # noqa: F401


def detail(report, rule):
    return next(f["detail"] for f in report["findings"] if f["rule_id"] == rule)


def test_an_index_set_for_every_login_is_a_redirect(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/usr/bin/pip3", "#!/bin/sh\n", 0o755)
    ps.baseline(manifest, root=str(root))
    place(root, "/etc/environment", 'PATH="/usr/bin"\nPIP_INDEX_URL="https://pypi.attacker.example/simple"\n')
    report = ps.check(manifest, root=str(root))
    assert [f["rule_id"] for f in report["findings"]] == ["PACKAGE_SOURCE_REDIRECTED"]
    assert detail(report, "PACKAGE_SOURCE_REDIRECTED") == (
        "index-url in pip for the system: https://pypi.org/simple → https://pypi.attacker.example/simple")
    state = ps.snapshot(root=str(root))
    [pip] = [s for s in state["sources"].values() if s["manager"] == "pip"]
    assert pip["set_in"] == "/etc/environment (PIP_INDEX_URL)", "says where and how it was set"


def test_the_environment_overrides_pip_s_own_file(root):
    place(root, "/etc/pip.conf", "[global]\nindex-url = https://pypi.internal.example/simple\n")
    place(root, "/etc/profile.d/proxy.sh", "export PIP_INDEX_URL=https://mirror.example/simple\n"
                                           "export PIP_TRUSTED_HOST='mirror.example other.example'\n")
    state = ps.snapshot(root=str(root))
    [pip] = [s for s in state["sources"].values() if s["manager"] == "pip"]
    assert (pip["uri"], pip["set_in"]) == ("https://mirror.example/simple", "/etc/profile.d/proxy.sh (PIP_INDEX_URL)")
    weakened = sorted(w["subject"] for w in state["weakenings"].values() if w["rule"] == "PACKAGE_TRANSPORT_WEAKENED")
    assert weakened == ["pip:the system:trusted-host:mirror.example", "pip:the system:trusted-host:other.example"]


def test_an_account_s_own_login_files_count_for_that_account(root, tmp_path):
    manifest = tmp_path / "packages.json"
    place(root, "/usr/bin/npm", "#!/bin/sh\n", 0o755)
    ps.baseline(manifest, root=str(root))
    place(root, "/home/dev/.bashrc", "alias ll='ls -l'\nexport NPM_CONFIG_REGISTRY=http://registry.example/\n"
                                     "NPM_CONFIG_STRICT_SSL=false\n")
    report = ps.check(manifest, root=str(root))
    # The account had no npm settings of its own at the baseline: its registry is a new source, set by its login.
    assert found(report) == [("HIGH", "PACKAGE_TRANSPORT_WEAKENED", "npm:account dev:plain:http://registry.example/"),
                             ("HIGH", "PACKAGE_TRANSPORT_WEAKENED", "npm:account dev:strict-ssl"),
                             ("MEDIUM", "PACKAGE_SOURCE_ADDED",
                              "source:npm npm http://registry.example/ npm for account dev registry")], \
        "npm reads its variables in any letter case"
    assert "set in /home/dev/.bashrc (npm_config_registry)" in detail(report, "PACKAGE_TRANSPORT_WEAKENED")
    assert not [f for f in report["findings"] if "the system" in f["subject"]], "other accounts are not touched"


def test_a_variable_that_names_another_config_file_is_followed(root):
    place(root, "/opt/ci/pip.conf", "[global]\nindex-url = https://ci-mirror.example/simple\n")
    place(root, "/etc/environment", "PIP_CONFIG_FILE=/opt/ci/pip.conf\n")
    [pip] = [s for s in ps.snapshot(root=str(root))["sources"].values() if s["manager"] == "pip"]
    assert (pip["uri"], pip["set_in"]) == ("https://ci-mirror.example/simple", "/opt/ci/pip.conf")


def test_a_value_built_by_the_shell_is_a_gap_not_a_guess(root):
    place(root, "/root/.profile", 'export PIP_INDEX_URL="$CORP_INDEX/simple"\n')
    state = ps.snapshot(root=str(root))
    assert "PIP_INDEX_URL in /root/.profile is built from other variables or commands: its value is not known" \
        in state["gaps"]
    assert not [s for s in state["sources"].values() if s["manager"] == "pip" and "CORP" in s["uri"]]


def test_others_who_can_change_the_system_environment_are_reported(root, tmp_path):
    place(root, "/etc/environment", 'LANG="C.UTF-8"\n', 0o666)
    report = ps.baseline(tmp_path / "packages.json", root=str(root))
    assert ("CRITICAL", "PACKAGE_CONFIG_WRITABLE", "file:/etc/environment") in found(report)


def test_a_path_written_with_a_double_slash_never_hangs_the_check(root):
    """POSIX keeps a leading //, and dirname('//etc') is '//': walking up to '/' must still end."""
    import signal

    def stuck(*_):
        raise AssertionError("walking up from //etc/... did not end")
    previous = signal.signal(signal.SIGALRM, stuck)
    signal.alarm(5)
    try:
        place(root, "/etc/profile.d/a.sh", "export PIP_INDEX_URL=https://mirror.example/simple\n", 0o666)
        found_writable = ps._guarded_writable(str(root), ["//etc/profile.d/a.sh"])
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert "//etc/profile.d/a.sh" in found_writable
