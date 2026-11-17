"""Fixed privileged host-input guard, independent of detector and AI decisions.

This self-contained source is sent through pkexec, following defense_guard's
fixed-helper boundary. No caller selects commands, paths or rule expressions.
"""
import hashlib
import ipaddress
import json
import math
import os
import selectors
import stat
import subprocess
import time

TABLE = 'megalodon_host_guard'
MARK = 'MEGALODON host protection v1 '
BASE = {'family': 'inet', 'table': TABLE}
DURATIONS = (900, 3600, 28800)


def policy_check(value):
    if type(value) is not dict or set(value) != {'services', 'duration_seconds'}:
        raise ValueError('Invalid host policy')
    if type(value['duration_seconds']) is not int or value['duration_seconds'] not in DURATIONS:
        raise ValueError('Invalid lease')
    if type(value['services']) is not list or len(value['services']) > 8:
        raise ValueError('Invalid services')
    seen = set()
    for row in value['services']:
        if type(row) is not dict or set(row) != {'protocol', 'port', 'source'}:
            raise ValueError('Invalid service')
        if type(row['protocol']) is not str or row['protocol'] not in ('tcp', 'udp'):
            raise ValueError('Invalid protocol')
        if type(row['port']) is not int or not 1 <= row['port'] <= 65535:
            raise ValueError('Invalid port')
        if type(row['source']) is not str or len(row['source']) > 49:
            raise ValueError('Invalid client network')
        net = ipaddress.ip_network(row['source'], strict=True)
        if str(net) != row['source'] or net.network_address.is_multicast or net.network_address.is_loopback:
            raise ValueError('Invalid client network')
        if net.version == 6 and net.prefixlen != 0 and (net.network_address.ipv4_mapped or any(
                net.overlaps(ipaddress.ip_network(p)) for p in ('64:ff9b::/96', '64:ff9b:1::/48'))):
            raise ValueError('Embedded IPv4 refused')
        key = (row['protocol'], row['port'], row['source'])
        if key in seen:
            raise ValueError('Duplicate service')
        seen.add(key)
    return value


def digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def objects(policy):
    """Closed JSON ruleset. A timed nfproto set gates every filtering decision."""
    policy_check(policy)
    rows = [
        {'table': {'family': 'inet', 'name': TABLE, 'comment': MARK + digest(policy)}},
        {'chain': {**BASE, 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -105, 'policy': 'accept'}},
        {'chain': {**BASE, 'name': 'shield'}},
        {'set': {**BASE, 'name': 'active', 'type': 'nf_proto', 'flags': ['timeout'], 'size': 2,
                 'timeout': policy['duration_seconds'], 'elem': [
                     {'elem': {'val': family, 'timeout': policy['duration_seconds']}} for family in ('ipv4', 'ipv6')]}},
    ]
    def rule(chain, expr, comment):
        rows.append({'rule': {**BASE, 'chain': chain, 'expr': expr, 'comment': comment}})
    accept = {'accept': None}
    counter = {'counter': {'packets': 0, 'bytes': 0}}
    rule('input', [match({'meta': {'key': 'nfproto'}}, '@active'), {'jump': {'target': 'shield'}}], 'lease')
    rule('shield', [match({'meta': {'key': 'iifname'}}, 'lo'), accept], 'loopback')
    rule('shield', [match({'ct': {'key': 'state'}}, 'invalid', 'in'), counter, {'drop': None}], 'invalid')
    rule('shield', [match({'ct': {'key': 'state'}}, ['established', 'related'], 'in'), accept], 'replies')
    rule('shield', [match(payload('icmpv6', 'type'), {'set': ['destination-unreachable', 'packet-too-big', 'time-exceeded', 'parameter-problem']}), accept], 'icmp6-errors')
    rule('shield', [match(payload('ip6', 'hoplimit'), 255), match(payload('icmpv6', 'type'), {'set': ['nd-router-advert', 'nd-neighbor-solicit', 'nd-neighbor-advert']}), accept], 'ipv6-neighbors')
    rule('shield', [match(payload('ip6', 'saddr'), {'prefix': {'addr': 'fe80::', 'len': 10}}),
                    match(payload('ip6', 'hoplimit'), 1), match(payload('icmpv6', 'type'), 'mld-listener-query'), accept], 'ipv6-multicast-query')
    rule('shield', [match(payload('ip', 'protocol'), 'icmp'), match(payload('icmp', 'type'), {'set': ['destination-unreachable', 'time-exceeded', 'parameter-problem']}), accept], 'icmp-errors')
    rule('shield', [match({'meta': {'key': 'nfproto'}}, 'ipv4'), match(payload('udp', 'sport'), 67), match(payload('udp', 'dport'), 68), accept], 'dhcp4-client')
    rule('shield', [match(payload('ip6', 'saddr'), {'prefix': {'addr': 'fe80::', 'len': 10}}), match(payload('udp', 'sport'), 547), match(payload('udp', 'dport'), 546), accept], 'dhcp6-client')
    for service in policy['services']:
        net = ipaddress.ip_network(service['source'])
        # nft removes redundant nfproto matches beside a source prefix. Use
        # just the family for /0; use a literal for a single-host prefix.
        source = str(net.network_address) if net.prefixlen == net.max_prefixlen else {
            'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}
        scope = match({'meta': {'key': 'nfproto'}}, 'ipv' + str(net.version)) if net.prefixlen == 0 else match(
            payload('ip' if net.version == 4 else 'ip6', 'saddr'), source)
        expr = [scope, match(payload(service['protocol'], 'dport'), service['port']), counter, accept]
        rule('shield', expr, 'service:' + json.dumps(service, sort_keys=True, separators=(',', ':')))
    rule('shield', [counter, {'drop': None}], 'unsolicited')
    return rows


def validate(document):
    """Reconstruct policy only from bounded service metadata, then compare all rules."""
    if type(document) is not dict or set(document) != {'nftables'}:
        raise ValueError('Unknown firewall document')
    rows = document['nftables']
    if type(rows) is not list or len(rows) > 32:
        raise ValueError('Unexpected firewall size')
    clean = []
    services = []
    duration = None
    remaining = []
    counts = {'invalid': 0, 'unsolicited': 0, 'allowed_service': 0}
    for row in rows:
        if type(row) is not dict or len(row) != 1:
            raise ValueError('Unknown object')
        kind, item = next(iter(row.items()))
        if kind == 'metainfo':
            continue
        if kind not in ('table', 'chain', 'set', 'rule') or type(item) is not dict:
            raise ValueError('Unknown object')
        item = dict(item)
        item.pop('handle', None)
        if kind == 'set':
            if duration is not None:
                raise ValueError('Extra set')
            duration = item.get('timeout')
            seen = set()
            for wrapper in item.pop('elem', []):
                if type(wrapper) is not dict or set(wrapper) != {'elem'}:
                    raise ValueError('Unknown lease')
                entry = wrapper['elem']
                if type(entry) is not dict or set(entry) - {'val', 'timeout', 'expires'}:
                    raise ValueError('Unknown lease')
                family, expiry = entry.get('val'), entry.get('expires')
                if (family not in ('ipv4', 'ipv6') or family in seen
                        or entry.get('timeout', duration) != duration
                        or type(expiry) not in (int, float) or not math.isfinite(expiry)
                        or not 0 <= expiry <= duration):
                    raise ValueError('Invalid lease')
                seen.add(family)
                remaining.append(expiry)
            # A partially changed lease is neither full protection nor proof
            # of inactivity. Do not hide a still-filtering family as inactive.
            if seen and seen != {'ipv4', 'ipv6'}:
                raise ValueError('Partial family lease requires review')
            if remaining and min(remaining) == 0 < max(remaining):
                raise ValueError('Partial family expiry requires review')
        if kind == 'rule':
            comment = item.get('comment', '')
            if type(comment) is not str or len(comment) > 128:
                raise ValueError('Unknown rule metadata')
            if comment.startswith('service:'):
                services.append(json.loads(comment[8:]))
            expr = []
            for statement in item.get('expr', []):
                if type(statement) is dict and 'counter' in statement:
                    counter = statement['counter']
                    if set(statement) != {'counter'} or type(counter) is not dict or set(counter) != {'packets', 'bytes'} or any(type(v) is not int or v < 0 for v in counter.values()):
                        raise ValueError('Invalid counter')
                    key = 'allowed_service' if comment.startswith('service:') else comment
                    if key in counts:
                        counts[key] += counter['packets']
                    expr.append({'counter': {'packets': 0, 'bytes': 0}})
                else:
                    expr.append(statement)
            item['expr'] = expr
        clean.append({kind: item})
    policy = policy_check({'services': services, 'duration_seconds': duration})
    expected = objects(policy)
    for row in expected:
        if 'set' in row:
            row['set'].pop('elem')
    # nft lists sets/chains by object class. Rule order within each chain matters.
    def grouped(items):
        return {kind: [r[kind] for r in items if kind in r] for kind in ('table', 'chain', 'set', 'rule')}
    if grouped(clean) != grouped(expected):
        raise ValueError('Managed policy changed; refusing to overwrite it')
    seconds = min(remaining, default=0)
    return dict(present=True, active=seconds > 0, remaining_seconds=seconds, policy=policy, counters=counts)


def check_binary():
    info = os.lstat('/usr/sbin/nft')
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ValueError('Untrusted system nft executable')


def nft(args, body=None):
    """Bounded subprocess output, fixed executable/environment/cwd, no shell."""
    import tempfile
    check_binary()
    with tempfile.TemporaryFile() as source:
        if body is not None:
            data = json.dumps(body, allow_nan=False).encode()
            if len(data) > 32768:
                raise ValueError('Oversized transaction')
            source.write(data)
            source.seek(0)
        process = subprocess.Popen(['/usr/sbin/nft', '-j', *args], stdin=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd='/',
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        try:
            output = bytearray()
            deadline = time.monotonic() + 5
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    timeout = deadline - time.monotonic()
                    if timeout <= 0 or not selector.select(timeout):
                        raise ValueError('Firewall inspection timed out')
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > 131072:
                        raise ValueError('Firewall output bound')
            code = process.wait(timeout=max(.001, deadline - time.monotonic()))
            return code, json.loads(output) if code == 0 and output.strip() else None
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def inspect():
    code, document = nft(['list', 'tables'])
    if code or type(document) is not dict or type(document.get('nftables')) is not list:
        raise ValueError('Cannot inspect firewall')
    if not any(row.get('table', {}).get('family') == 'inet' and row.get('table', {}).get('name') == TABLE for row in document['nftables']):
        return dict(present=False, active=False, remaining_seconds=0, policy=None,
                    counters={'invalid': 0, 'unsolicited': 0, 'allowed_service': 0})
    code, document = nft(['list', 'table', 'inet', TABLE])
    if code:
        raise ValueError('Cannot inspect managed policy')
    return validate(document)


def act(action, policy):
    if action not in ('apply', 'remove', 'status'):
        raise ValueError('Unknown action')
    if action == 'apply':
        policy_check(policy)
    elif policy != {}:
        raise ValueError('Unexpected policy')
    before = inspect()
    commands = []
    if action in ('apply', 'remove') and before['present']:
        commands.append({'delete': {'table': {'family': 'inet', 'name': TABLE}}})
    if action == 'apply':
        commands.extend({'add': row} for row in objects(policy))
    if commands:
        code, _ = nft(['-f', '-'], {'nftables': commands})
        if code:
            raise ValueError('Host protection transaction failed')
    result = inspect()
    if action == 'apply' and (not result['active'] or result['policy'] != policy):
        raise ValueError('Host protection was not verified')
    if action == 'remove' and result['present']:
        raise ValueError('Removal was not verified')
    return dict(result, verified=True)


def main():
    import fcntl
    import sys
    if os.geteuid() != 0 or len(sys.argv) != 3 or len(sys.argv[2]) > 2048:
        raise ValueError('OS authorization required')
    fd = os.open('/run/lock/megalodon-host-guard.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Untrusted guard lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(act(sys.argv[1], json.loads(sys.argv[2])), allow_nan=False))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import sys
        print('Host protection could not be verified. The existing lease, if any, still expires in the kernel.', file=sys.stderr)
        sys.exit(2)
