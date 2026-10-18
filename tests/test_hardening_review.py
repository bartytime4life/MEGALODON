"""Read-only hardening checks over a synthetic /proc and /etc tree."""
import hashlib
import json
import os
import subprocess

import pytest

from megalodon import hardening_review, provider_containment
from megalodon.hardening_review import SCHEMA, STATES, listeners, main, review

NOW = '2026-10-18T05:00:00Z'
GOOD = {'kernel/randomize_va_space': '2', 'kernel/kptr_restrict': '1', 'kernel/dmesg_restrict': '1',
        'kernel/yama/ptrace_scope': '1', 'fs/protected_symlinks': '1', 'fs/protected_hardlinks': '1',
        'fs/suid_dumpable': '0', 'net/ipv4/tcp_syncookies': '1', 'net/ipv4/conf/all/rp_filter': '1',
        'net/ipv4/conf/all/accept_redirects': '0', 'net/ipv6/conf/all/accept_redirects': '0',
        'net/ipv4/conf/all/accept_source_route': '0', 'net/ipv4/ip_forward': '0'}
TCP_HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'


def row(local, state):
    return f'   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1\n'


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('hardening review must never run a program')
    for name in ('run', 'Popen', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, 'system', refuse)


@pytest.fixture(autouse=True)
def little_endian_tables(monkeypatch):
    monkeypatch.setattr(provider_containment, '_BYTE_ORDER', 'little')


@pytest.fixture
def root(tmp_path):
    for rel, value in GOOD.items():
        path = tmp_path/'proc/sys'/rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value+'\n')
    (tmp_path/'proc/net').mkdir(parents=True)
    (tmp_path/'proc/net/tcp').write_text(TCP_HEADER + row('0100007F:0277', '0A'))
    (tmp_path/'etc/apt/apt.conf.d').mkdir(parents=True)
    (tmp_path/'etc/apt/apt.conf.d/20auto-upgrades').write_text('APT::Periodic::Unattended-Upgrade "1";\n')
    return tmp_path


def by_id(result):
    return {check['id']: check for check in result['checks']}


def test_hardened_tree_passes_and_reports_shape(root):
    result = review(root, now=lambda: NOW)
    assert result['schema'] == SCHEMA and result['action_authority'] == 'none'
    checks = by_id(result)
    assert all(checks[c[0]]['state'] == 'pass' for c in hardening_review.SYSCTL)
    assert checks['ip_forward']['state'] == 'pass' and checks['auto_updates']['state'] == 'pass'
    assert checks['exposed_listeners']['state'] == 'pass'
    assert {checks[c[0]]['state'] for c in hardening_review.SSH} == {'not_applicable'}
    assert all(c['action_status'] == 'not_attempted' and c['state'] in STATES for c in result['checks'])
    assert sum(result['summary'].values()) == len(result['checks'])


def test_weak_missing_and_unreadable_parameters(root):
    (root/'proc/sys/kernel/kptr_restrict').write_text('0\n')
    (root/'proc/sys/kernel/yama/ptrace_scope').unlink()
    (root/'proc/sys/fs/suid_dumpable').unlink()
    (root/'proc/sys/fs/suid_dumpable').mkdir()
    (root/'proc/sys/net/ipv4/ip_forward').write_text('1\n')
    checks = by_id(review(root))
    assert checks['kptr_restrict']['state'] == 'fail' and checks['kptr_restrict']['observed'] == '0'
    assert checks['ptrace_scope']['state'] == 'unknown' and checks['ptrace_scope']['observed'] == 'not present'
    assert checks['suid_dumpable']['state'] == 'unknown' and checks['suid_dumpable']['observed'] == 'unreadable'
    assert checks['ip_forward']['state'] == 'review' and 'Container runtimes' in checks['ip_forward']['note']


def test_ssh_defaults_includes_first_value_and_match(root):
    ssh = root/'etc/ssh'
    (ssh/'sshd_config.d').mkdir(parents=True)
    (ssh/'sshd_config.d/10-local.conf').write_text('PasswordAuthentication no\n')
    (ssh/'sshd_config').write_text('Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n'
                                   'Include /etc/../tmp/evil.conf\nMatch User backup\n  PermitRootLogin yes\n')
    checks = by_id(review(root))
    assert checks['ssh_password_auth']['state'] == 'pass' and checks['ssh_password_auth']['observed'] == 'no'
    root_login = checks['ssh_root_login']
    # sshd would read the refused outside include, so the default is not assumed.
    assert root_login['state'] == 'unknown'
    assert 'Match blocks' in root_login['note'] and 'outside /etc/ssh' in root_login['note']
    (ssh/'sshd_config').write_text('Include /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n  PermitRootLogin yes\n')
    root_login = by_id(review(root))['ssh_root_login']
    assert root_login['state'] == 'pass' and 'OpenSSH default' in root_login['observed']


def test_ssh_failures_and_symlinked_include(root, tmp_path_factory):
    ssh = root/'etc/ssh'
    (ssh/'sshd_config.d').mkdir(parents=True)
    outside = tmp_path_factory.mktemp('outside')/'x.conf'
    outside.write_text('PasswordAuthentication no\n')
    (ssh/'sshd_config.d/link.conf').symlink_to(outside)
    (ssh/'sshd_config').write_text('Include sshd_config.d/*.conf\nPermitRootLogin yes\nPermitEmptyPasswords yes\n')
    checks = by_id(review(root))
    # The refused include comes first, so it could set an earlier, winning value.
    assert checks['ssh_root_login']['state'] == 'unknown'
    assert checks['ssh_root_login']['observed'] == 'yes (an earlier unread section may set it first)'
    # The refused include might set it, so the OpenSSH default is not assumed.
    assert checks['ssh_password_auth']['state'] == 'unknown'
    assert 'could not be read' in checks['ssh_password_auth']['note']


def test_apt_last_setting_wins_and_non_apt_hosts(root):
    (root/'etc/apt/apt.conf.d/99-off').write_text('// local\nAPT::Periodic::Unattended-Upgrade "0";\n')
    assert by_id(review(root))['auto_updates']['state'] == 'fail'
    (root/'etc/apt/apt.conf.d/99-off').unlink()
    (root/'etc/apt/apt.conf.d/20auto-upgrades').unlink()
    assert by_id(review(root))['auto_updates']['observed'] == 'not configured'
    for path in (root/'etc/apt/apt.conf.d').iterdir():
        path.unlink()
    (root/'etc/apt/apt.conf.d').rmdir()
    assert by_id(review(root))['auto_updates']['state'] == 'not_applicable'


def test_listeners_exclude_loopback_and_non_listening_sockets(root):
    (root/'proc/net/tcp').write_text(TCP_HEADER + row('00000000:0016', '0A') + row('0100007F:0277', '0A')
                                     + row('0F02000A:9C40', '01'))
    (root/'proc/net/tcp6').write_text(TCP_HEADER + row('0'*32 + ':0050', '0A') + row('0'*24 + '01000000:0BB8', '0A')
                                      + row('0000000000000000FFFF00000100007F:1F90', '0A'))
    found, complete = listeners(root)
    assert complete and found == [dict(family='ipv4', address='0.0.0.0', port=22), dict(family='ipv6', address='::', port=80)]
    check = by_id(review(root))['exposed_listeners']
    assert check['state'] == 'review' and check['observed'] == '0.0.0.0:22, :::80'
    assert 'firewall may still block' in check['note']


def test_listener_bound_and_unreadable_table(root, monkeypatch):
    monkeypatch.setattr(hardening_review, 'MAX_LISTENERS', 2)
    (root/'proc/net/tcp').write_text(TCP_HEADER + ''.join(row(f'00000000:{port:04X}', '0A') for port in range(1, 6)))
    found, complete = listeners(root)
    assert len(found) == 2 and complete is False
    (root/'proc/net/tcp').unlink()
    (root/'proc/net/tcp').mkdir()
    check = by_id(review(root))['exposed_listeners']
    assert check['state'] == 'unknown' and check['observed'] == 'socket table not fully read'
    assert check['listeners_complete'] is False and 'not fully read' in check['note']


def test_review_never_writes(root):
    def digest():
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
    before = digest()
    review(root)
    assert digest() == before


def test_cli_prints_json(capsys, monkeypatch, root):
    monkeypatch.setattr(hardening_review, 'review', lambda: review(root, now=lambda: NOW))
    assert main([]) == 0
    assert json.loads(capsys.readouterr().out)['reviewed_at'] == NOW


def test_large_socket_table_is_read_and_truncation_disclosed(root, monkeypatch):
    sockets = ''.join(row(f'0F02000A:{port:04X}', '01') for port in range(1, 2000))
    (root/'proc/net/tcp').write_text(TCP_HEADER + sockets + row('00000000:0016', '0A'))
    assert (root/'proc/net/tcp').stat().st_size > hardening_review.MAX_READ
    found, complete = listeners(root)
    assert found == [dict(family='ipv4', address='0.0.0.0', port=22)] and complete is True
    monkeypatch.setattr(hardening_review, 'MAX_TABLE_READ', 4096)
    found, complete = listeners(root)
    assert found == [] and complete is False
    check = by_id(review(root))['exposed_listeners']
    assert check['state'] == 'unknown' and check['listeners_complete'] is False


def test_ssh_tab_separators_and_oversized_config(root, monkeypatch):
    ssh = root/'etc/ssh'
    ssh.mkdir(parents=True)
    (ssh/'sshd_config').write_text('PasswordAuthentication\tno\nPermitRootLogin=no\n')
    checks = by_id(review(root))
    assert checks['ssh_password_auth']['observed'] == 'no' and checks['ssh_root_login']['observed'] == 'no'
    monkeypatch.setattr(hardening_review, 'MAX_READ', 16)
    note = by_id(review(root))['ssh_root_login']['note']
    assert 'only its start was read' in note


def test_apt_file_bound_is_disclosed(root, monkeypatch):
    monkeypatch.setattr(hardening_review, 'MAX_APT_FILES', 2)
    for index in range(4):
        (root/'etc/apt/apt.conf.d'/f'{index:02d}-x').write_text('')
    check = by_id(review(root))['auto_updates']
    assert check['note'] == 'Only the first 2 of 5 APT configuration files were read.'


def test_missing_socket_tables_are_never_a_pass(root):
    (root/'proc/net/tcp').unlink()
    check = by_id(review(root))['exposed_listeners']
    assert check['state'] == 'unknown' and check['listeners_complete'] is False
    (root/'proc/net/tcp').write_text(TCP_HEADER)
    assert by_id(review(root))['exposed_listeners']['state'] == 'pass'  # IPv6 absent: no if_inet6
    (root/'proc/net/if_inet6').write_text('')
    check = by_id(review(root))['exposed_listeners']
    assert check['state'] == 'unknown' and check['listeners_complete'] is False


@pytest.mark.parametrize('make, observed', [(lambda p: p.unlink(), 'not present'),
                                            (lambda p: (p.unlink(), p.mkdir()), 'unreadable')])
def test_ip_forward_row_is_always_reported(root, make, observed):
    make(root/'proc/sys/net/ipv4/ip_forward')
    check = by_id(review(root))['ip_forward']
    assert check['state'] == 'unknown' and check['observed'] == observed


def test_truncated_ssh_config_does_not_assume_defaults(root, monkeypatch):
    ssh = root/'etc/ssh'
    ssh.mkdir(parents=True)
    (ssh/'sshd_config').write_text('PermitRootLogin no\n' + '# padding\n' * 40 + 'PermitEmptyPasswords yes\n')
    monkeypatch.setattr(hardening_review, 'MAX_READ', 64)
    checks = by_id(review(root))
    assert checks['ssh_root_login']['state'] == 'pass'  # established before the cut-off
    assert checks['ssh_empty_passwords']['state'] == 'unknown'
    assert checks['ssh_empty_passwords']['observed'] == 'not set in the configuration that was read'


def test_apt_comments_are_ignored(root):
    (root/'etc/apt/apt.conf.d/20auto-upgrades').write_text(
        '/*\nAPT::Periodic::Unattended-Upgrade "1";\n*/\n# APT::Periodic::Unattended-Upgrade "1";\n')
    check = by_id(review(root))['auto_updates']
    assert check['state'] == 'fail' and check['observed'] == 'not configured'


def test_apt_pass_needs_every_file_read(root, monkeypatch):
    (root/'etc/apt/apt.conf.d/99-dir').mkdir()
    check = by_id(review(root))['auto_updates']
    assert check['state'] == 'unknown' and '1 APT configuration files could not be fully read.' in check['note']
    (root/'etc/apt/apt.conf.d/99-dir').rmdir()
    monkeypatch.setattr(hardening_review, 'MAX_APT_FILES', 1)
    (root/'etc/apt/apt.conf.d/99-later').write_text('APT::Periodic::Unattended-Upgrade "0";\n')
    assert by_id(review(root))['auto_updates']['state'] == 'unknown'


def test_values_after_an_unread_include_are_not_certain(root, tmp_path_factory):
    ssh = root/'etc/ssh'
    (ssh/'sshd_config.d').mkdir(parents=True)
    outside = tmp_path_factory.mktemp('outside')/'x.conf'
    outside.write_text('PermitRootLogin yes\n')
    (ssh/'sshd_config.d/00-link.conf').symlink_to(outside)
    (ssh/'sshd_config').write_text('PermitEmptyPasswords no\nInclude sshd_config.d/*.conf\nPermitRootLogin no\n')
    checks = by_id(review(root))
    assert checks['ssh_empty_passwords']['state'] == 'pass'  # read before the gap
    assert checks['ssh_root_login']['state'] == 'unknown'


def test_include_glob_overflow_marks_the_read_incomplete(root, monkeypatch):
    monkeypatch.setattr(hardening_review, 'MAX_SSH_INCLUDES', 2)
    ssh = root/'etc/ssh'
    (ssh/'sshd_config.d').mkdir(parents=True)
    for name in ('a', 'b'):
        (ssh/'sshd_config.d'/f'{name}.conf').write_text('# nothing\n')
    (ssh/'sshd_config.d/z.conf').write_text('PermitRootLogin yes\n')
    (ssh/'sshd_config').write_text('Include sshd_config.d/*.conf\n')
    check = by_id(review(root))['ssh_root_login']
    assert check['state'] == 'unknown' and 'matched more than 2 files' in check['note']


def test_partial_final_line_of_a_truncated_ssh_file_is_not_parsed(root, monkeypatch):
    ssh = root/'etc/ssh'
    (ssh/'sshd_config.d').mkdir(parents=True)
    (ssh/'sshd_config.d/10-safe').write_text('PasswordAuthentication no\n')
    head = 'PermitRootLogin no\nInclude /etc/ssh/sshd_config.d/10-safe'
    (ssh/'sshd_config').write_text(head + '-extra\n')
    monkeypatch.setattr(hardening_review, 'MAX_READ', len(head))
    checks = by_id(review(root))
    assert checks['ssh_root_login']['state'] == 'pass'  # a complete line before the cut
    # The cut-off Include is not mistaken for the existing 10-safe file.
    assert checks['ssh_password_auth']['state'] == 'unknown'
