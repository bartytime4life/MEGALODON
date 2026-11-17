"""Opt-in real packet acceptance, ONLY inside a fresh user/network namespace.

Run with MEGALODON_TEST_PARENT_NET set to the caller's network namespace link,
then unshare --user --map-root-user --net .venv312/bin/python this-file.
No interface or firewall in the caller's host namespace is touched.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon import host_guard as guard


def ip(*args):
    subprocess.run(['/usr/sbin/ip', *args], check=True, capture_output=True, timeout=5)


def echo_server(family, port, udp=False):
    server = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', port))
    if not udp:
        server.listen(16)
    def echo(connection):
        with connection:
            while data := connection.recv(128):
                connection.sendall(data)
    def serve():
        while True:
            try:
                if udp:
                    data, address = server.recvfrom(128)
                    server.sendto(data, address)
                else:
                    connection, _ = server.accept()
                    threading.Thread(target=echo, args=(connection,), daemon=True).start()
            except OSError:
                break
    threading.Thread(target=serve, daemon=True).start()
    return server


def exchange(address, port, udp=False, source_port=None):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as client:
        client.settimeout(.3)
        if source_port:
            client.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', source_port))
        try:
            client.connect((address, port))
            client.sendall(b'test')
            return client.recv(128) == b'test'
        except (TimeoutError, OSError):
            return False


def peer():
    print('ready', flush=True)
    kept = None
    servers = []
    for raw in sys.stdin:
        command = json.loads(raw)
        if command['action'] == 'init':
            ip('link', 'set', 'lo', 'up')
            ip('addr', 'add', '198.18.0.2/24', 'dev', 'mg-peer')
            ip('-6', 'addr', 'add', 'fd42::2/64', 'dev', 'mg-peer', 'nodad')
            ip('link', 'set', 'mg-peer', 'up')
            servers = [echo_server(f, 18083) for f in (socket.AF_INET, socket.AF_INET6)]
            answer = True
        elif command['action'] == 'keep':
            kept = socket.create_connection(('198.18.0.1', 18080), timeout=.5)
            answer = True
        elif command['action'] == 'existing':
            kept.sendall(b'existing')
            answer = kept.recv(128) == b'existing'
        else:
            answer = exchange(command['address'], command['port'], command.get('udp', False), command.get('source_port'))
        print(json.dumps(answer), flush=True)


def main():
    uid_map = Path('/proc/self/uid_map').read_text().split()
    parent_net = os.environ.get('MEGALODON_TEST_PARENT_NET')
    if not parent_net or os.geteuid() != 0 or len(uid_map) != 3 or uid_map[-1] != '1' or os.readlink('/proc/self/ns/net') == parent_net:
        raise SystemExit('Refusing: disposable user AND network namespace required.')
    # A single-user namespace presents host root-owned binaries as overflow UID.
    # Only this harness skips executable ownership; unit tests cover its refusals.
    guard.check_binary = lambda: None
    assert not guard.nft(['list', 'tables'])[1]['nftables'][1:], 'namespace must start empty'
    child = subprocess.Popen(['unshare', '--net', sys.executable, __file__, 'peer'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    servers = []
    checks = []
    def check(label, condition):
        assert condition, label
        checks.append(label)
    def call(action, **kw):
        child.stdin.write(json.dumps(dict(action=action, **kw)) + '\n')
        child.stdin.flush()
        return json.loads(child.stdout.readline())
    def incoming(address, port=18080, **kw):
        return call('exchange', address=address, port=port, **kw)
    try:
        assert child.stdout.readline().strip() == 'ready'
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'mg-host', 'type', 'veth', 'peer', 'name', 'mg-peer')
        ip('link', 'set', 'mg-peer', 'netns', str(child.pid))
        ip('addr', 'add', '198.18.0.1/24', 'dev', 'mg-host')
        ip('-6', 'addr', 'add', 'fd42::1/64', 'dev', 'mg-host', 'nodad')
        ip('link', 'set', 'mg-host', 'up')
        call('init')
        for family in (socket.AF_INET, socket.AF_INET6):
            servers.extend([echo_server(family, 18080), echo_server(family, 18081), echo_server(family, 18082, True), echo_server(family, 68, True)])
        # Exercise preservation of tracked sessions under an existing firewall.
        guard.nft(['-f', '-'], {'nftables': [
            {'add': {'table': {'family': 'inet', 'name': 'unrelated_test'}}},
            {'add': {'chain': {'family': 'inet', 'table': 'unrelated_test', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'accept'}}},
            {'add': {'rule': {'family': 'inet', 'table': 'unrelated_test', 'chain': 'input', 'expr': [guard.match({'ct': {'key': 'state'}}, ['established', 'related'], 'in'), {'accept': None}]}}},
        ]})
        check('baseline IPv4 and IPv6 inbound', incoming('198.18.0.1') and incoming('fd42::1'))
        call('keep')
        policy = {'duration_seconds': 900, 'services': []}
        check('atomic apply with verified lease', guard.act('apply', policy)['active'])
        check('existing inbound preserved', call('existing'))
        check('unsolicited TCP IPv4 and IPv6 dropped', not incoming('198.18.0.1', 18081) and not incoming('fd42::1', 18081))
        check('unsolicited UDP IPv4 and IPv6 dropped', not incoming('198.18.0.1', 18082, udp=True) and not incoming('fd42::1', 18082, udp=True))
        check('host initiated IPv4 and IPv6 connections preserved', exchange('198.18.0.2', 18083) and exchange('fd42::2', 18083))
        check('loopback preserved', exchange('127.0.0.1', 18081) and exchange('::1', 18081))
        check('DHCPv4 client exception', incoming('198.18.0.1', 68, udp=True, source_port=67))
        check('DHCPv4 exception cannot open IPv6 UDP port', not incoming('fd42::1', 68, udp=True, source_port=67))
        check('drop counts from real packets', guard.act('status', {})['counters']['unsolicited'] >= 4)
        policy['services'] = [{'protocol': 'tcp', 'port': 18081, 'source': '198.18.0.2/32'}, {'protocol': 'udp', 'port': 18082, 'source': 'fd42::2/128'}]
        check('renew with explicit service policy', guard.act('apply', policy)['active'])
        check('per-source IPv4 TCP exception works', incoming('198.18.0.1', 18081))
        check('per-source IPv6 UDP exception works', incoming('fd42::1', 18082, udp=True))
        check('TCP exception cannot open same IPv6 port', not incoming('fd42::1', 18081))
        check('UDP exception cannot open same IPv4 port', not incoming('198.18.0.1', 18082, udp=True))
        check('allowed service packet counts', guard.act('status', {})['counters']['allowed_service'] >= 2)
        # Shorten ONLY the two test kernel elements. The shipped helper has no
        # caller-selected short lease and cannot silently renew these elements.
        guard.nft(['-f', '-'], {'nftables': [
            {'flush': {'set': {**guard.BASE, 'name': 'active'}}},
            {'add': {'element': {**guard.BASE, 'name': 'active', 'elem': [
                {'elem': {'val': family, 'timeout': 1}} for family in ('ipv4', 'ipv6')]}}},
        ]})
        time.sleep(1.2)
        check('kernel expiry without HUD or helper', incoming('198.18.0.1') and incoming('fd42::1'))
        check('expired readback is inactive', not guard.act('status', {})['active'])
        check('removal verified', not guard.act('remove', {})['present'])
        check('unrelated firewall table preserved', any(r.get('table', {}).get('name') == 'unrelated_test' for r in guard.nft(['list', 'tables'])[1]['nftables']))
        check('traffic recovers after removal', incoming('198.18.0.1', 18081) and incoming('fd42::1', 18081))
        # A changed rule is a conflict, never an excuse to flush an owner's table.
        guard.act('apply', policy)
        guard.nft(['add', 'rule', 'inet', guard.TABLE, 'shield', 'accept'])
        for action, value in [('apply', policy), ('remove', {})]:
            try:
                guard.act(action, value)
            except ValueError:
                checks.append('foreign rule refuses ' + action)
            else:
                raise AssertionError('foreign policy overwritten')
        print(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))
    finally:
        child.terminate()
        child.wait(timeout=3)
        for server in servers:
            server.close()


if __name__ == '__main__':
    peer() if sys.argv[1:] == ['peer'] else main()
