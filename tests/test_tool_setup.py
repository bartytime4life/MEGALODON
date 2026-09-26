import json
from types import SimpleNamespace
import pytest
from megalodon import tool_setup
from megalodon.tool_installer import RECIPES


def test_all_tools_have_nonexecuting_setup_and_configuration(monkeypatch,capsys):
    assert set(tool_setup.CONFIGURATION)==set(RECIPES)
    monkeypatch.setattr(tool_setup.subprocess,'run',lambda *a,**k: pytest.fail('preview executed a process'))
    for tool in RECIPES:
        assert tool_setup.main([tool])==0
        assert tool_setup.main([tool,'install'])==0
        assert tool_setup.main([tool,'configure'])==0
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
