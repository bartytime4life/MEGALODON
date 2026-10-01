"""Repository entry point installs once and uses fixed local launch paths."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() == 0, reason='Linux desktop user launcher')
SCRIPT = Path(__file__).resolve().parents[1] / 'Start-MEGALODON.sh'


@pytest.fixture
def launcher(tmp_path):
    repo = tmp_path / "repo with spaces ' $(touch SHOULD_NOT_EXIST)"
    repo.mkdir()
    script = repo / SCRIPT.name
    shutil.copy2(SCRIPT, script)
    home = tmp_path / 'operator'
    binary = home / '.local/bin/megalodon-hud'
    binary.parent.mkdir(parents=True)
    binary.write_text(f'#!{sys.executable}\nimport os\nfrom pathlib import Path\nPath(os.environ["TEST_OPENED"]).write_text("opened")\n')
    binary.chmod(0o700)
    python = tmp_path / 'test-python'
    python.write_text(f'''#!{sys.executable}
import sys, os, json
from pathlib import Path
args=sys.argv[1:]
if '-c' in args: sys.exit(0)
with open(os.environ['TEST_CALLS'],'a') as log: log.write(json.dumps(args)+'\\n')
if 'status' in args: sys.exit(0 if Path(os.environ['TEST_READY']).exists() else 1)
if 'install' in args:
    if os.environ.get('TEST_INSTALL_FAIL'): sys.exit(2)
    Path(os.environ['TEST_READY']).touch()
''')
    python.chmod(0o700)
    env = dict(os.environ, HOME=str(home), MEGALODON_PYTHON=str(python),
               TEST_CALLS=str(tmp_path/'calls'), TEST_READY=str(tmp_path/'ready'), TEST_OPENED=str(tmp_path/'opened'))
    return script, env


def run(launcher, *args):
    script, env = launcher
    return subprocess.run([str(script), *args], env=env, cwd='/', capture_output=True, text=True, timeout=5)


def test_initial_install_then_repeat_launch_without_reinstall(launcher):
    script, env = launcher
    assert run(launcher).returncode == 0
    assert Path(env['TEST_OPENED']).read_text() == 'opened'
    assert run(launcher).returncode == 0
    calls = [json.loads(line) for line in Path(env['TEST_CALLS']).read_text().splitlines()]
    installs = [args for args in calls if 'install' in args]
    assert installs == [['-E','-s','-m','megalodon.local_install','install','--source',str(script.parent)]]
    assert not (script.parent/'SHOULD_NOT_EXIST').exists()
    assert all('enable' not in args for args in calls)


def test_failed_install_does_not_open_hud(launcher):
    _, env = launcher
    env['TEST_INSTALL_FAIL']='1'
    assert run(launcher).returncode == 2
    assert not Path(env['TEST_OPENED']).exists()


def test_check_and_unknown_options_do_not_start_or_install(launcher):
    _, env = launcher
    assert run(launcher, '--check').returncode == 1
    assert run(launcher, '--unknown').returncode == 2
    calls = [json.loads(line) for line in Path(env['TEST_CALLS']).read_text().splitlines()]
    assert calls == [['-E','-s','-m','megalodon.local_install','status']]
    assert not Path(env['TEST_OPENED']).exists()
