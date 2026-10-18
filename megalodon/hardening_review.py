"""Read-only hardening posture checks for this Linux host. Advice only; nothing is changed.

Each check reads one fixed kernel parameter, SSH daemon setting, update
setting or socket table and reports pass, fail, review, unknown or
not_applicable with the observed value and a remediation note. A pass is not
proof the host is secure, and a fail is not proof it is compromised; distro
defaults, containers and deliberate operator choices all affect the result.
Applying a remediation is always a separate operator decision.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import glob
import heapq
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

from .provider_containment import _LISTEN_STATE, _TCP_TABLES, _parse_address

SCHEMA = 'megalodon-hardening-review-v1'
MAX_READ = 64 * 1024
MAX_TABLE_READ = 16 * 1024 * 1024
MAX_APT_FILES = 256
MAX_SSH_INCLUDES = 32
MAX_LISTENERS = 64
MAX_TABLE_LINES = 65536
STATES = ('pass', 'fail', 'review', 'unknown', 'not_applicable')
_APT_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
# (id, path under /proc/sys, accepted values, ATT&CK mitigation, title, remediation)
SYSCTL = (
    ('aslr', 'kernel/randomize_va_space', {'2'}, 'M1050', 'Full address space layout randomization',
     'Set kernel.randomize_va_space = 2 in /etc/sysctl.d/.'),
    ('kptr_restrict', 'kernel/kptr_restrict', {'1', '2'}, 'M1028', 'Kernel pointers hidden from unprivileged users',
     'Set kernel.kptr_restrict = 1 or 2.'),
    ('dmesg_restrict', 'kernel/dmesg_restrict', {'1'}, 'M1028', 'Kernel log restricted to privileged users',
     'Set kernel.dmesg_restrict = 1.'),
    ('ptrace_scope', 'kernel/yama/ptrace_scope', {'1', '2', '3'}, 'M1028', 'Process tracing limited to descendants or administrators',
     'Set kernel.yama.ptrace_scope = 1 or higher; debuggers may then need sudo.'),
    ('protected_symlinks', 'fs/protected_symlinks', {'1'}, 'M1028', 'Symlink following restricted in sticky directories',
     'Set fs.protected_symlinks = 1.'),
    ('protected_hardlinks', 'fs/protected_hardlinks', {'1'}, 'M1028', 'Hardlink creation restricted to owned files',
     'Set fs.protected_hardlinks = 1.'),
    ('suid_dumpable', 'fs/suid_dumpable', {'0'}, 'M1028', 'No core dumps from privileged programs',
     'Set fs.suid_dumpable = 0.'),
    ('syncookies', 'net/ipv4/tcp_syncookies', {'1'}, 'M1037', 'TCP SYN cookies enabled',
     'Set net.ipv4.tcp_syncookies = 1.'),
    ('rp_filter', 'net/ipv4/conf/all/rp_filter', {'1', '2'}, 'M1037', 'Reverse-path filtering of spoofed source addresses',
     'Set net.ipv4.conf.all.rp_filter = 1 (strict) or 2 (loose).'),
    ('ipv4_redirects', 'net/ipv4/conf/all/accept_redirects', {'0'}, 'M1037', 'IPv4 ICMP redirects ignored',
     'Set net.ipv4.conf.all.accept_redirects = 0.'),
    ('ipv6_redirects', 'net/ipv6/conf/all/accept_redirects', {'0'}, 'M1037', 'IPv6 ICMP redirects ignored',
     'Set net.ipv6.conf.all.accept_redirects = 0.'),
    ('source_route', 'net/ipv4/conf/all/accept_source_route', {'0'}, 'M1037', 'Source-routed packets refused',
     'Set net.ipv4.conf.all.accept_source_route = 0.'),
)
# OpenSSH defaults applied when a keyword is not set before the first Match block.
SSH = (
    ('ssh_root_login', 'permitrootlogin', 'prohibit-password', {'no', 'prohibit-password', 'without-password'}, 'M1026',
     'SSH root login without a password is refused', 'Set PermitRootLogin no in /etc/ssh/sshd_config.d/.'),
    ('ssh_password_auth', 'passwordauthentication', 'yes', {'no'}, 'M1032',
     'SSH password authentication disabled in favour of keys', 'Set PasswordAuthentication no after confirming key login works.'),
    ('ssh_empty_passwords', 'permitemptypasswords', 'no', {'no'}, 'M1027',
     'SSH refuses accounts with empty passwords', 'Set PermitEmptyPasswords no.'),
)
# Every review emits exactly these checks, in this order; a reader can reject any other set.
CHECK_IDS = tuple(c[0] for c in SYSCTL) + ('ip_forward',) + tuple(c[0] for c in SSH) + ('auto_updates', 'exposed_listeners')


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _text(value, limit=160):
    value = ''.join(c if c.isprintable() else '?' for c in str(value))
    return value if len(value) <= limit else value[:limit]+'...'


def _read(path, limit=None):
    """Return (text, truncated) for a bounded regular file, without following a final symlink."""
    limit = MAX_READ if limit is None else limit
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('not a regular file')
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
        data = b''.join(chunks)
        return data[:limit].decode('utf-8', 'replace'), size > limit
    finally:
        os.close(fd)


def _check(check_id, title, state, observed, expected, mitigation, remediation, note=None):
    row = dict(id=check_id, title=title, state=state, observed=_text(observed), expected=expected,
               mitigation=mitigation, remediation=remediation, action_status='not_attempted')
    if note:
        row['note'] = note
    return row


def sysctl_checks(root):
    rows = []
    for check_id, rel, accepted, mitigation, title, remediation in SYSCTL:
        expected = ' or '.join(sorted(accepted))
        try:
            value = _read(Path(root, 'proc/sys', rel))[0].strip()
        except FileNotFoundError:
            rows.append(_check(check_id, title, 'unknown', 'not present', expected, mitigation, remediation,
                               'This kernel does not expose the parameter, or the view is restricted.'))
            continue
        except (OSError, ValueError):
            rows.append(_check(check_id, title, 'unknown', 'unreadable', expected, mitigation, remediation))
            continue
        rows.append(_check(check_id, title, 'pass' if value in accepted else 'fail', value, expected, mitigation, remediation))
    try:
        forward = _read(Path(root, 'proc/sys/net/ipv4/ip_forward'))[0].strip()
    except FileNotFoundError:
        forward = 'not present'
    except (OSError, ValueError):
        forward = 'unreadable'
    if forward in ('not present', 'unreadable'):
        rows.append(_check('ip_forward', 'IPv4 packet forwarding', 'unknown', forward, '0', 'M1037',
                           'Set net.ipv4.ip_forward = 0 unless this host routes for others.'))
    else:
        rows.append(_check('ip_forward', 'IPv4 packet forwarding', 'pass' if forward == '0' else 'review', forward, '0', 'M1037',
                           'Set net.ipv4.ip_forward = 0 unless this host routes for others.',
                           None if forward == '0' else 'Container runtimes, VPNs and routers enable forwarding on purpose.'))
    return rows


def _ssh_settings(root):
    """Return {keyword: (value, certain)}, coverage notes, and whether all text was read.

    sshd reads includes in place and keeps the first value of each keyword,
    so any text skipped before a keyword's first value could have set it
    earlier. Such a value is not certain, and an unset keyword after any skip
    has no established default.
    """
    settings, notes, seen = {}, [], set()
    complete = True
    def gap(message):
        nonlocal complete
        notes.append(message); complete = False
    def parse(path, depth):
        if depth > 2 or len(seen) > MAX_SSH_INCLUDES or path in seen:
            gap('Some SSH include files were not read.'); return False
        seen.add(path)
        text, truncated = _read(path)
        if truncated:
            # The cut can land inside a directive; only complete lines are parsed.
            text = text.rpartition('\n')[0]
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # sshd accepts spaces, tabs or a single "=" between keyword and value.
            parts = line.replace('=', ' ', 1).split(None, 1)
            key, value = parts[0].lower(), (parts[1] if len(parts) > 1 else '').split('#', 1)[0].strip()
            if key == 'match':
                notes.append('Settings inside Match blocks apply conditionally and were not evaluated.')
                return True
            if key == 'include':
                for pattern in value.split():
                    pattern = pattern if pattern.startswith('/') else '/etc/ssh/'+pattern
                    # Only follow includes that stay under /etc/ssh.
                    if not os.path.normpath(pattern).startswith('/etc/ssh/'):
                        gap('An SSH include outside /etc/ssh was not read.'); continue
                    matches = heapq.nsmallest(MAX_SSH_INCLUDES + 1, glob.iglob(str(Path(root, pattern.lstrip('/')))))
                    for match in matches[:MAX_SSH_INCLUDES]:
                        try:
                            if parse(match, depth+1):
                                return True
                        except (OSError, ValueError):
                            gap('An SSH include file could not be read.')
                    if len(matches) > MAX_SSH_INCLUDES:
                        gap(f'An SSH include pattern matched more than {MAX_SSH_INCLUDES} files; the rest were not read.')
                continue
            if key not in settings:
                settings[key] = (value.lower(), complete)
        if truncated:
            # The unread tail comes after everything parsed above.
            gap(f'An SSH configuration file is larger than {MAX_READ // 1024} KiB; only its start was read.')
        return False
    parse(str(Path(root, 'etc/ssh/sshd_config')), 0)
    return settings, list(dict.fromkeys(notes)), complete


def ssh_checks(root):
    path = Path(root, 'etc/ssh/sshd_config')
    if not os.path.lexists(path):
        return [_check(c[0], c[5], 'not_applicable', 'no sshd_config', ' or '.join(sorted(c[3])), c[4], c[6],
                       'The OpenSSH server configuration is not present.') for c in SSH]
    try:
        settings, notes, complete = _ssh_settings(root)
    except (OSError, ValueError):
        return [_check(c[0], c[5], 'unknown', 'unreadable', ' or '.join(sorted(c[3])), c[4], c[6]) for c in SSH]
    rows = []
    for check_id, key, default, accepted, mitigation, title, remediation in SSH:
        value, certain = settings.get(key, (None, complete))
        note = ' '.join(notes) or None
        if value is None and not complete:
            # The keyword may be set in text that was not read; the default is not established.
            rows.append(_check(check_id, title, 'unknown', 'not set in the configuration that was read',
                               ' or '.join(sorted(accepted)), mitigation, remediation, note))
            continue
        if not certain:
            # Text skipped before this value could hold an earlier, winning value.
            rows.append(_check(check_id, title, 'unknown', f'{value} (an earlier unread section may set it first)',
                               ' or '.join(sorted(accepted)), mitigation, remediation, note))
            continue
        observed = value if value is not None else f'{default} (OpenSSH default; not set)'
        rows.append(_check(check_id, title, 'pass' if (value or default) in accepted else 'fail', observed,
                           ' or '.join(sorted(accepted)), mitigation, remediation, note))
    return rows


def update_checks(root):
    directory = Path(root, 'etc/apt/apt.conf.d')
    if not directory.is_dir():
        return [_check('auto_updates', 'Automatic security updates', 'not_applicable', 'no APT configuration', 'enabled', 'M1051',
                       'Enable your distribution\'s automatic security update service.', 'Only APT-based systems are checked.')]
    enabled, total = None, 0
    def names():
        nonlocal total
        with os.scandir(directory) as entries:
            for entry in entries:
                total += 1
                yield entry.name
    # APT reads these files in name order, so the last setting wins.
    unread = 0
    for name in heapq.nsmallest(MAX_APT_FILES, names()):
        try:
            text, truncated = _read(directory/name)
        except (OSError, ValueError):
            unread += 1; continue
        unread += truncated
        # APT ignores /* */ blocks and // or # line comments.
        text = _APT_BLOCK_COMMENT.sub(' ', text)
        for line in text.splitlines():
            line = line.split('//', 1)[0].strip()
            if line.startswith('#'):
                continue
            if line.startswith('APT::Periodic::Unattended-Upgrade'):
                enabled = '"1"' in line or '"true"' in line.lower()
    notes = []
    if total > MAX_APT_FILES:
        notes.append(f'Only the first {MAX_APT_FILES} of {total} APT configuration files were read.')
    if unread:
        notes.append(f'{unread} APT configuration files could not be fully read.')
    note = ' '.join(notes) or None
    if enabled and notes:
        # A later, unread file could still disable the setting.
        return [_check('auto_updates', 'Automatic security updates', 'unknown', 'enabled in the files that were read', 'enabled',
                       'M1051', 'Set APT::Periodic::Unattended-Upgrade "1".', note)]
    if enabled is None:
        return [_check('auto_updates', 'Automatic security updates', 'fail', 'not configured', 'enabled', 'M1051',
                       'Install unattended-upgrades and run "dpkg-reconfigure unattended-upgrades".', note)]
    return [_check('auto_updates', 'Automatic security updates', 'pass' if enabled else 'fail', 'enabled' if enabled else 'disabled',
                   'enabled', 'M1051', 'Set APT::Periodic::Unattended-Upgrade "1".', note)]


def _loopback(address):
    value = ipaddress.ip_address(address)
    mapped = getattr(value, 'ipv4_mapped', None)
    return value.is_loopback or bool(mapped and mapped.is_loopback)


def listeners(root):
    """Return non-loopback TCP listeners and whether both tables were fully read."""
    found, complete = [], True
    for family, rel, length in _TCP_TABLES:
        try:
            # Busy hosts have large tables; a cut-off read is reported, never treated as complete.
            text, truncated = _read(Path(root, rel.lstrip('/')), MAX_TABLE_READ)
        except FileNotFoundError:
            # A missing IPv4 table means procfs is unavailable; a missing IPv6
            # table is complete only when IPv6 itself is absent.
            if family != 'ipv6' or os.path.lexists(Path(root, 'proc/net/if_inet6')):
                complete = False
            continue
        except (OSError, ValueError):
            complete = False; continue
        lines = text.splitlines()
        if truncated or len(lines) > MAX_TABLE_LINES:
            complete = False
            lines = lines[:MAX_TABLE_LINES] if not truncated else lines[:-1][:MAX_TABLE_LINES]
        lines = lines[1:]
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != _LISTEN_STATE or ':' not in fields[1]:
                continue
            address_hex, _, port_hex = fields[1].partition(':')
            address = _parse_address(address_hex, length)
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            if address is None or _loopback(address):
                continue
            row = dict(family=family, address=address, port=port)
            if row not in found:
                found.append(row)
            if len(found) >= MAX_LISTENERS:
                return found, False
    return found, complete


def listener_checks(root):
    found, complete = listeners(root)
    title, remediation = 'No TCP services listen beyond this computer', 'Stop or bind to 127.0.0.1 any service that need not be reachable from the network.'
    partial = None if complete else 'The socket tables were not fully read, so other listeners may exist.'
    if not found:
        return [dict(_check('exposed_listeners', title, 'pass' if complete else 'unknown',
                            'none' if complete else 'socket table not fully read', 'none', 'M1042', remediation, partial),
                     listeners_complete=complete)]
    shown = ', '.join(f"{r['address']}:{r['port']}" for r in found[:12]) + (' ...' if len(found) > 12 else '')
    note = ' '.join(filter(None, ['Listening is not exposure: a firewall may still block these ports. '
                                  'Process names need root and are not shown.', partial]))
    return [dict(_check('exposed_listeners', title, 'review', shown, 'none', 'M1042', remediation, note),
                 listeners=found, listeners_complete=complete)]


def review(root='/', now=_now):
    checks = sysctl_checks(root) + ssh_checks(root) + update_checks(root) + listener_checks(root)
    return dict(schema=SCHEMA, reviewed_at=now(), checks=checks,
                summary={state: sum(c['state'] == state for c in checks) for state in STATES},
                action_authority='none',
                limitations=['Checks read live settings; a value changed at runtime may differ from boot configuration.',
                             'A pass does not establish that the host is secure; a fail does not establish compromise.',
                             'Firewall rules, root-only files and per-interface overrides are not evaluated.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)
    try:
        print(json.dumps(review(), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('Hardening review unavailable: '+_text(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
