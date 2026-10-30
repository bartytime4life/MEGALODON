"""Independent structural checks; no engine pass is inferred."""
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import unittest
import generate


class FixtureTests(unittest.TestCase):
    def test_reproducible(self):
        self.assertEqual(generate.artifacts(), generate.artifacts())
        for name, data in generate.artifacts().items():
            self.assertEqual(data, (Path(__file__).parent / name).read_bytes())

    def test_packets_and_checksums(self):
        data = generate.artifacts()['netmask.pcap']
        self.assertEqual(len(data), 256)
        self.assertEqual(struct.unpack('<IHHIIII', data[:24]), (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        offset = 24
        for i, source in enumerate(generate.SOURCES, 1):
            seconds, micros, captured, original = struct.unpack('<IIII', data[offset:offset+16])
            self.assertEqual((seconds, micros, captured, original), (1700000000+i, 0, 42, 42))
            frame = data[offset+16:offset+16+captured]
            self.assertEqual(frame[:14], bytes.fromhex('0200000000020200000000010800'))
            ip, udp = frame[14:34], frame[34:]
            self.assertEqual(str(ipaddress.IPv4Address(ip[12:16])), source)
            self.assertEqual(str(ipaddress.IPv4Address(ip[16:20])), generate.DESTINATION)
            for block in (ip, ip[12:20] + bytes.fromhex('00110008') + udp):
                total = sum(struct.unpack('!'+'H'*(len(block)//2), block))
                while total >> 16:
                    total = (total & 65535) + (total >> 16)
                self.assertEqual(total, 65535)
            self.assertEqual(struct.unpack('!HHHH', udp)[:3], (40000+i, 40099, 8))
            offset += 16 + captured
        self.assertEqual(offset, len(data))

    def test_oracle_and_manifest(self):
        files = generate.artifacts()
        matrix = json.loads(files['expected.json'])
        network = ipaddress.ip_network('192.0.2.0/24')
        self.assertEqual(matrix['expected_alert_count'], 4)
        for row in matrix['rows']:
            expected = [9900101, 9900102] if ipaddress.ip_address(row['src_ip']) in network else []
            self.assertEqual(row['expected_sids'], expected)
        manifest = json.loads(files['manifest.json'])
        self.assertFalse(manifest['suricata_executed'])
        self.assertFalse(manifest['acceptance_authority'])
        for name, identity in manifest['artifacts'].items():
            self.assertEqual(identity['sha256'], hashlib.sha256(files[name]).hexdigest())
        rules = files['local.rules'].decode().splitlines()
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].replace('/24', '/255.255.255.0').replace('9900101', '9900102'), rules[1])


if __name__ == '__main__':
    unittest.main()
