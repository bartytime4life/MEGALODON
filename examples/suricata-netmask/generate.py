"""Synthetic fixture preparation only. No producer, network or shell execution."""
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

SOURCES = ('192.0.2.1', '192.0.2.254', '198.51.100.1', '203.0.113.1')
DESTINATION = '203.0.113.200'


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source, index):
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(DESTINATION).packed
    udp = struct.pack('!HHHH', 40000 + index, 40099, 8, 0)
    check = checksum(src + dst + struct.pack('!BBH', 0, 17, 8) + udp) or 65535
    udp = udp[:6] + struct.pack('!H', check)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, index, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('0200000000020200000000010800') + ip + udp


def artifacts():
    pcap = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index, source in enumerate(SOURCES, 1):
        frame = packet(source, index)
        pcap += struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)) + frame
    rules = ''.join(
        f'alert ip 192.0.2.0/{mask} any -> any any (msg:"Synthetic netmask equivalence"; sid:{sid}; rev:1;)\n'
        for mask, sid in [('24', 9900101), ('255.255.255.0', 9900102)]
    ).encode()
    oracle = {
        'status': 'expected_not_observed',
        'expected_alert_count': 4,
        'rows': [{'packet': i, 'src_ip': source, 'dest_ip': DESTINATION,
                  'expected_sids': [9900101, 9900102] if i <= 2 else []}
                 for i, source in enumerate(SOURCES, 1)],
        'comparison': 'Exact multiset of (src_ip,dest_ip,signature_id); order irrelevant; duplicates fail.',
    }
    files = {'netmask.pcap': pcap, 'local.rules': rules,
             'expected.json': (json.dumps(oracle, sort_keys=True, indent=2) + '\n').encode()}
    manifest = {
        'schema': 'megalodon-netmask-fixture-v1', 'status': 'prepared_not_run',
        'candidate_version': '8.0.8', 'binary_identity': 'unbound',
        'source': 'https://redmine.openinfosecfoundation.org/issues/9171',
        'suricata_executed': False, 'acceptance_authority': False,
        'fixture_license': 'Apache-2.0 (independently authored project fixtures)',
        'artifacts': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                      for name, data in files.items()},
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'proposed_limits': {'packets': 4, 'pcap_bytes': 256, 'wall_seconds': 10,
                            'address_space_bytes': 536870912, 'output_bytes': 1048576,
                            'packet_processing_threads': 1},
    }
    files['manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    return files


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New directory only; never overwrite')
    args = parser.parse_args()
    files = artifacts()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in files.items():
        with (args.output / name).open('xb') as stream:
            stream.write(data)
