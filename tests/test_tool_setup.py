import json
from types import SimpleNamespace
import pytest
from megalodon import tool_setup
from megalodon.tool_installer import RECIPES
from megalodon import tool_installer
from pathlib import Path
import subprocess


def test_all_tools_have_nonexecuting_setup_and_configuration(monkeypatch,capsys):
    assert set(tool_setup.CONFIGURATION)==set(RECIPES)
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda *a,**k: pytest.fail('preview executed a process'))
    for tool in RECIPES:
        assert tool_setup.main([tool])==0
        assert tool_setup.main([tool,'install'])==0
        assert tool_setup.main([tool,'configure'])==0
        assert tool_setup.main([tool,'uninstall'])==0
        assert 'no configuration changed' in capsys.readouterr().out


def test_only_explicit_apply_executes_fixed_recipe(monkeypatch):
    calls=[]
    monkeypatch.setattr(tool_setup,'install_command',lambda tool:['fixed',tool])
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda command,**kw: calls.append((command,kw)) or SimpleNamespace(returncode=0))
    assert tool_setup.main(['nmap','install','--apply'])==0
    assert calls[0][0]==['fixed','nmap']
    assert calls[0][1]['timeout']==1800
    with pytest.raises(SystemExit):tool_setup.main(['nmap','configure','--apply'])
    with pytest.raises(SystemExit):tool_setup.main(['nmap; echo nope'])
    assert len(calls)==1


def test_guided_install_and_presence_do_not_claim_configuration(monkeypatch,capsys):
    monkeypatch.setattr(tool_setup,'install_command',lambda tool:None)
    assert tool_setup.main(['ossec','install','--apply'])==2
    capsys.readouterr()
    for tool in RECIPES:
        assert tool_setup.main([tool,'verify'])==0
        value=json.loads(capsys.readouterr().out)
        assert value['presence'] in {'not_checked','not_found','executable_found'}
        assert 'running state are not verified' in value['boundaries'][0]


def test_uninstall_is_closed_preview_and_requires_terminal_confirmation(monkeypatch, capsys):
    calls=[]
    monkeypatch.setattr(tool_installer.os,'geteuid',lambda:1000)
    monkeypatch.setattr(tool_installer,'runtime_platform',lambda:'linux')
    which={'sudo':'/usr/bin/sudo','apt-get':'/usr/bin/apt-get','ollama':'/usr/bin/ollama'}.get
    assert tool_installer.uninstall_command('tshark',which=which)==['/usr/bin/sudo','/usr/bin/apt-get','remove','--no-install-recommends','tshark']
    assert tool_installer.uninstall_command('qwen',which=which)==['/usr/bin/ollama','rm','qwen2.5:7b']
    assert tool_installer.uninstall_command('scapy',which=which)[-2:]==['uninstall','scapy']
    monkeypatch.setattr(tool_installer.os,'geteuid',lambda:0)
    assert tool_installer.uninstall_command('nmap',which=which) is None
    monkeypatch.setattr(tool_installer.os,'geteuid',lambda:1000)
    for guided in ('core','zeek','osquery','ossec','greenbone','nftables'):
        assert tool_installer.uninstall_command(guided,which=which) is None
    assert tool_installer.terminal_command('core','uninstall')=='~/.local/bin/megalodon-manage uninstall'
    assert tool_installer.terminal_command('nftables','uninstall') is None
    monkeypatch.setattr(tool_setup,'uninstall_command',lambda tool:['fixed',tool])
    monkeypatch.setattr(tool_setup,'preview_apt_removal',lambda tool,command: True)
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda command,**kw: calls.append(command) or SimpleNamespace(returncode=0))
    monkeypatch.setattr(tool_setup.sys,'stdin',SimpleNamespace(isatty=lambda:False))
    assert tool_setup.main(['nmap','uninstall','--apply'])==2
    assert not calls
    monkeypatch.setattr(tool_setup.sys,'stdin',SimpleNamespace(isatty=lambda:True))
    monkeypatch.setattr('builtins.input',lambda prompt:'wrong')
    assert tool_setup.main(['nmap','uninstall','--apply'])==2
    assert not calls
    monkeypatch.setattr('builtins.input',lambda prompt:'nmap')
    assert tool_setup.main(['nmap','uninstall','--apply'])==0
    assert calls==[['fixed','nmap']]


def test_apt_removal_plan_is_unprivileged_and_failure_prevents_confirmation(monkeypatch, capsys):
    calls=[]
    def run(command, **kwargs):
        calls.append((command,kwargs))
        return SimpleNamespace(returncode=0, stdout='The following packages will be REMOVED:\n  nmap nmap-dependant\n', stderr='')
    monkeypatch.setattr(tool_setup.subprocess,'run',run)
    monkeypatch.setattr(tool_setup.sys,'stdin',SimpleNamespace(isatty=lambda:True))
    monkeypatch.setattr(tool_setup,'uninstall_command',lambda tool:['/usr/bin/sudo','/usr/bin/apt-get','remove','--no-install-recommends','nmap'])
    monkeypatch.setattr('builtins.input',lambda prompt:'wrong')
    assert tool_setup.main(['nmap','uninstall','--apply'])==2
    assert [call[0] for call in calls]==[['/usr/bin/apt-get','-s','remove','--no-install-recommends','nmap']]
    assert 'nmap-dependant' in capsys.readouterr().out
    assert calls[0][1]['timeout']==30
    assert calls[0][1]['env']['LC_ALL']=='C'
    calls.clear()
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda command,**kwargs: SimpleNamespace(returncode=100,stdout='',stderr='error'))
    monkeypatch.setattr('builtins.input',lambda prompt: pytest.fail('confirmation reached after failed simulation'))
    assert tool_setup.main(['nmap','uninstall','--apply'])==2


def test_apt_removal_plan_rejects_oversized_output(monkeypatch):
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda command,**kwargs: SimpleNamespace(returncode=0,stdout='x'*(tool_setup.APT_PREVIEW_MAX_CHARS+1),stderr=''))
    assert not tool_setup.preview_apt_removal('nmap',['sudo','apt-get','remove','nmap'])


def test_example_model_removal_is_pinned_to_loopback(monkeypatch):
    seen=[]
    monkeypatch.setattr(tool_setup,'uninstall_command',lambda tool:['ollama','rm','qwen2.5:7b'])
    monkeypatch.setattr(tool_setup.sys,'stdin',SimpleNamespace(isatty=lambda:True))
    monkeypatch.setattr('builtins.input',lambda prompt:'qwen')
    monkeypatch.setenv('OLLAMA_HOST','remote.example:11434')
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda command,**kw: seen.append((command,kw)) or SimpleNamespace(returncode=0))
    assert tool_setup.main(['qwen','uninstall','--apply'])==0
    assert seen[0][0]==['ollama','rm','qwen2.5:7b']
    assert seen[0][1]['env']['OLLAMA_HOST']=='127.0.0.1:11434'


def test_companion_shell_entry_stays_with_fixed_python_module():
    script=Path(__file__).resolve().parents[1]/'scripts/manage-companion.sh'
    source=script.read_text()
    assert 'exec "$local_python" -m megalodon.tool_setup "$@"' in source
    result=subprocess.run(['bash',str(script),'nmap','uninstall'],capture_output=True,text=True,timeout=10)
    assert result.returncode==0 and 'Uninstall command:' in result.stdout
    assert 'Preview only.' in result.stdout
    refused=subprocess.run(['bash',str(script),'nmap; echo nope','install'],capture_output=True,text=True,timeout=10)
    assert refused.returncode!=0
