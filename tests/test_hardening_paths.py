"""Root's command search path as root's own shell files, cron and root's services set it, not only the system's."""
from __future__ import annotations

import os

from megalodon import hardening_drift as hd
from test_hardening_drift import GOOD, reviewer, root, rules  # noqa: F401


def place(base, path, text, mode=0o644):
    target = base / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    os.chmod(target, mode)


def sources(base):
    return [where for where, _value in hd._paths(str(base))]


def writable(base, folder):
    (base / folder.lstrip("/")).mkdir(parents=True, exist_ok=True)
    os.chmod(base / folder.lstrip("/"), 0o777)


def test_root_s_own_shell_files(root, tmp_path):  # noqa: F811
    place(root, "/root/.profile", 'if [ -d "$HOME/bin" ]; then\n    PATH="$HOME/bin:$PATH"\nfi\n'
                                  "export PATH=/srv/deploy/bin:$PATH  # the deploy tools\n")
    place(root, "/root/.bashrc", "PATH=~/.local/bin:${PATH}:$UNKNOWN/bin:`pwd`\nPATH=.:$PATH\n")
    found = dict(hd._paths(str(root)))
    assert found["/root/.profile PATH"] == "/srv/deploy/bin", "the last assignment in a file, $HOME expanded"
    assert ("/root/.bashrc PATH", "/root/.local/bin") in hd._paths(str(root)), "~ is /root; unknowns left out"
    assert ("/root/.bashrc PATH", ".") in hd._paths(str(root))
    writable(root, "/srv/deploy/bin")
    folders, _programs, relative = hd.search_path(str(root))
    assert folders["/srv/deploy/bin"]["set_in"] == "/root/.profile PATH" and relative == {".": "/root/.bashrc PATH"}


def test_cron_paths(root):  # noqa: F811
    place(root, "/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/bin:/opt/cron-tools\n"
                                "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    place(root, "/etc/cron.d/backup", 'PATH="/srv/backup/bin:/usr/bin"\n0 3 * * * root backup-all\n')
    place(root, "/var/spool/cron/crontabs/root", "PATH=/root/bin\n* * * * * job\n", 0o600)
    found = dict(hd._paths(str(root)))
    assert found["/etc/crontab PATH"] == "/usr/local/sbin:/usr/bin:/opt/cron-tools"
    assert found["/etc/cron.d/backup PATH"] == "/srv/backup/bin:/usr/bin"
    assert found["/var/spool/cron/crontabs/root PATH"] == "/root/bin"


def test_services_that_run_as_root(root):  # noqa: F811
    place(root, "/etc/systemd/system.conf", "[Manager]\nDefaultEnvironment=LANG=C PATH=/usr/bin:/opt/everyone\n")
    place(root, "/lib/systemd/system/agent.service", '[Service]\nEnvironment="PATH=/opt/agent/bin:/usr/bin" X=1\n'
                                                     "ExecStart=/opt/agent/bin/agent\n")
    place(root, "/lib/systemd/system/web.service", "[Service]\nUser=www-data\nEnvironment=PATH=/srv/www/bin\n")
    place(root, "/lib/systemd/system/sync.service", "[Service]\nEnvironmentFile=-/etc/default/sync\n")
    place(root, "/etc/default/sync", 'PATH="/srv/sync/bin:%h/bin"\n')
    place(root, "/lib/systemd/system/tool.service", "[Unit]\nEnvironment=PATH=/not/service/section\n[Service]\n")
    place(root, "/lib/systemd/system/fleeting.service", "[Service]\nDynamicUser=yes\nEnvironment=PATH=/srv/dyn\n")
    found = dict(hd._paths(str(root)))
    assert found["/etc/systemd/system.conf DefaultEnvironment"] == "/usr/bin:/opt/everyone"
    assert found["agent.service: /lib/systemd/system/agent.service Environment"] == "/opt/agent/bin:/usr/bin"
    assert found["sync.service: /etc/default/sync (EnvironmentFile of sync.service)"] == "/srv/sync/bin"
    assert not [w for w in found if w.startswith(("web.service", "tool.service", "fleeting.service"))], \
        "services running as another account, and PATH outside [Service], are not root's"


def test_a_unit_in_etc_overrides_and_drop_ins_apply_in_order(root):  # noqa: F811
    place(root, "/lib/systemd/system/agent.service", "[Service]\nEnvironment=PATH=/opt/packaged/bin\n")
    place(root, "/etc/systemd/system/agent.service", "[Service]\nEnvironment=PATH=/opt/local/bin\n")
    place(root, "/etc/systemd/system/agent.service.d/10-path.conf", "[Service]\nEnvironment=PATH=/opt/dropin/bin\n")
    place(root, "/lib/systemd/system/plain.service", "[Service]\nEnvironment=PATH=/opt/packaged/plain\n")
    place(root, "/etc/systemd/system/plain.service", "[Service]\nEnvironment=PATH=/opt/local/plain\n")
    place(root, "/lib/systemd/system/svc.service", "[Service]\nEnvironment=PATH=/opt/svc/bin\n")
    place(root, "/etc/systemd/system/svc.service.d/50-user.conf", "[Service]\nUser=svc\n")
    place(root, "/lib/systemd/system/reset.service", "[Service]\nEnvironment=PATH=/opt/reset/bin\nEnvironment=\n")
    found = dict(hd._paths(str(root)))
    assert found["agent.service: /etc/systemd/system/agent.service.d/10-path.conf Environment"] == "/opt/dropin/bin"
    assert found["plain.service: /etc/systemd/system/plain.service Environment"] == "/opt/local/plain", \
        "a unit in /etc replaces the packaged one"
    assert not [w for w in found if w.startswith(("svc.service", "reset.service"))], \
        "a drop-in that sets another account applies; an empty Environment= clears the list"


def test_a_service_s_writable_folder_is_reported_with_where_it_was_set(root, tmp_path):  # noqa: F811
    manifest = tmp_path / "hardening.json"
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    place(root, "/lib/systemd/system/agent.service", "[Service]\nEnvironment=PATH=/opt/agent/bin:/usr/bin\n")
    writable(root, "/opt/agent/bin")
    report = hd.check(manifest, review=reviewer(GOOD), budget=30)
    assert rules(report) == [("CRITICAL", "PATH_FOLDER_WRITABLE", "file:/opt/agent/bin")]
    assert "set in agent.service: /lib/systemd/system/agent.service Environment" in report["findings"][0]["detail"]


def test_specifiers_in_a_unit_file(root):  # noqa: F811
    place(root, "/lib/systemd/system/home.service", "[Service]\nEnvironment=PATH=%h/bin:/opt/%i/bin:/usr/bin\n")
    assert dict(hd._paths(str(root)))["home.service: /lib/systemd/system/home.service Environment"] == \
        "/root/bin:/usr/bin", "%h is root's home; an instance name is not known"
