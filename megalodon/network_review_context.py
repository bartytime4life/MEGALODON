"""Reviewed networking interpretation cues for local model explanations.

These are short paraphrases of the linked RFCs in docs/network-review-context.md.
They supply context only; observed facts, citations and workflow authority stay
in the existing evidence and validation path.
"""

CONTEXT = {
    'OBSERVED_ACTIVITY': 'If NAT translation is present, an observed public tuple does not identify one internal device. Observation alone does not establish that NAT was used (RFC 4787).',
    'PORT_SCAN': 'This detector counts distinct destination ports per source across TCP packets, not distinct destination hosts or SYN attempts. Repeated packets to one port do not increase that count; the finding does not prove intent or completed connections (RFC 9293).',
    'SYN_FLOOD': 'TCP can retransmit SYN after loss. Packet counts alone do not establish unique handshakes or target resource exhaustion (RFC 9293).',
    'DNS_TUNNELING': 'This detector requires dns_query_length metadata on a DNS or UDP event, with no destination-port condition. A long query can be legitimate; its length alone does not prove tunneling, reveal query content or cover all resolver activity (RFC 7766, RFC 7858, RFC 8484).',
    'PORT_53_BURST': 'DNS can use UDP, TCP, TLS or HTTPS. Port 53 observations are not a count of parsed DNS questions (RFC 7766, RFC 7858, RFC 8484).',
    'NEW_DESTINATION_PORT': 'A transport port is not an application identity. QUIC uses UDP, while TLS protects application data (RFC 9000, RFC 8446).',
    'PROTOCOL_SHIFT': 'A TCP-to-UDP shift can reflect QUIC use; transport metadata alone cannot identify the application or establish the cause (RFC 9000).',
    'SERVICE_SHIFT': 'A sensor service label is an observation, not proof of an application. QUIC is a secure UDP-based transport (RFC 9000).',
}


def for_pattern(rule: str) -> str:
    return CONTEXT.get(rule, '')
