"""Offline investigation notes over observed endpoints; no origin attribution."""
from datetime import datetime
from ipaddress import ip_address

SCHEMA = 'megalodon-address-investigation-v1'
REGISTRY_SEARCH = 'https://search.arin.net/rdap/'
MAX_COUNT = 2**53 - 1  # Exact in both JSON consumers and Python.
TCP_FLAGS = frozenset({'FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'})
PORT_CLUES = {
    ('TCP', 1080): 'SOCKS-associated port',
    ('TCP', 3128): 'HTTP proxy-associated port',
    ('TCP', 8080): 'HTTP alternate / proxy-associated port',
    ('TCP', 8118): 'HTTP proxy-associated port',
    ('TCP', 9050): 'SOCKS-associated port',
    ('TCP', 9150): 'SOCKS-associated port',
    ('TCP', 1194): 'OpenVPN-associated port',
    ('UDP', 1194): 'OpenVPN-associated port',
    ('UDP', 51820): 'WireGuard-associated port',
    ('UDP', 500): 'IPsec key-exchange-associated port',
    ('UDP', 4500): 'IPsec NAT-traversal-associated port',
}


def _text(value, limit=160):
    return value if type(value) is str and 0 < len(value) <= limit and value.isprintable() else None


def _stamp(value):
    if not _text(value, 40):
        return None
    try:
        return value if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is not None else None
    except ValueError:
        return None


def _count(value):
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def investigate(endpoint, *, recording_mode=None, coverage=None):
    """Keep observation, relay clues, network registration and identity separate."""
    address = ip_address(endpoint['ip'])
    # Python maintenance releases differ on mapped IPv6 is_reserved. Keep this
    # lookup policy explicit instead of inheriting that version-dependent flag.
    public = (address.is_global and not address.is_multicast and not address.is_reserved
              and getattr(address, 'ipv4_mapped', None) is None)
    ports, clues, seen = [], [], set()
    for row in endpoint.get('ports', [])[:32]:
        protocol, port = row.get('protocol'), row.get('port')
        if protocol not in {'TCP', 'UDP'} or type(port) is not int or not 0 <= port <= 65535 or (protocol, port) in seen:
            continue
        seen.add((protocol, port))
        ports.append(dict(protocol=protocol, port=port))
        label = PORT_CLUES.get((protocol, port))
        if label:
            clues.append(dict(protocol=protocol, port=port, label=label))
    names = []
    for row in endpoint.get('names', [])[:5]:
        name, source = _text(row.get('name'), 253), _text(row.get('source'), 128)
        if name and source:
            names.append(dict(name=name, source=source, observed_at=_stamp(row.get('observed_at'))))
    traffic = {key: _count(endpoint.get(key)) for key in
               ('connections', 'active_connections', 'packets', 'bytes', 'sent_bytes', 'received_bytes')}
    traffic['direction_basis'] = 'relative_to_observed_address'
    traffic['tcp_flags'] = sorted({flag for flag in endpoint.get('flags', [])[:8] if flag in TCP_FLAGS})
    traffic['protocols'] = list(dict.fromkeys(p for p in endpoint.get('protocols', [])[:16] if _text(p, 32)))
    sources = []
    for row in endpoint.get('measurement_sources', [])[:8]:
        source = _text(row.get('source'), 128)
        basis = row.get('byte_basis')
        if source and basis in {'reported_bytes', 'ip_bytes', 'payload_bytes', 'unknown'}:
            sources.append(dict(source=source, byte_basis=basis))
    traffic['measurement_sources'] = sources
    coverage = coverage or {}
    context = dict(
        recording_mode=recording_mode if recording_mode in {'packet_metadata', 'connection_summaries'} else 'not_recorded',
        window_seconds=_count(coverage.get('window_seconds')),
        truncated=coverage.get('truncated') if type(coverage.get('truncated')) is bool else None,
        capture_gaps='unknown',
        notes=[note for note in coverage.get('notes', [])[:8] if _text(note, 512)],
    )
    return dict(
        schema=SCHEMA, observed_address=str(address), public_address=public,
        first_seen=_stamp(endpoint.get('first_seen')), last_seen=_stamp(endpoint.get('last_seen')),
        source='retained_connection_metadata', origin_status='not_established',
        original_address=None, person_identity=None, relay_status='not_established',
        relay_clues=clues, observed_ports=ports, observed_names=names,
        traffic=traffic, observation_context=context,
        network_holder_status='not_recorded', network_holder=None,
        registry_search_url=REGISTRY_SEARCH if public else None,
        network_access_performed=False, action_authority='none',
        limitations=[
            'The observed endpoint can be a VPN exit, proxy, NAT gateway, shared host or direct peer. Its original source is not established.',
            'Port associations are investigation clues; they do not prove that a VPN or proxy is in use.',
            'Observed hostnames describe an exchange and do not identify the owner of this address.',
            'A registry record can identify a network holder, not the person making a connection.',
            'Tracing beyond a relay requires separately obtained, trustworthy records from that relay. Forwarded headers alone can be forged.',
        ],
    )
