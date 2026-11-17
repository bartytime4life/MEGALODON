"""Reviewed networking interpretation cues for local model explanations.

These are short paraphrases of the linked RFCs in docs/network-review-context.md.
They supply context only; observed facts, citations and workflow authority stay
in the existing evidence and validation path.
"""

CONTEXT = {
    'OBSERVED_ACTIVITY': 'If NAT translation is present, an observed public tuple does not identify one internal device. Observation alone does not establish that NAT was used (RFC 4787).',
    'PORT_SCAN': 'This detector counts distinct destination ports per source across TCP candidates without ACK or RST, not distinct destination hosts or packet count. Repeated probes to one port do not increase that count. ACK-only scans require stateful analysis; the finding does not prove intent or completed connections (RFC 9293).',
    'SYN_FLOOD': 'TCP can retransmit SYN after loss. Packet counts alone do not establish unique handshakes or target resource exhaustion (RFC 9293).',
    'DNS_TUNNELING': 'This detector requires dns_query_length metadata on a DNS or UDP event, with no destination-port condition. A long query can be legitimate; its length alone does not prove tunneling, reveal query content or cover all resolver activity (RFC 7766, RFC 7858, RFC 8484).',
    'BRUTE_FORCE': 'This detector counts TCP connection attempts (SYN without ACK, or flagless flow records) from one source to one host and authentication port. A connection attempt is not a login attempt, and TLS or SSH multiplexing can hide retries (RFC 9293, RFC 4253).',
    'HOST_SWEEP': 'This detector counts distinct private, CGNAT, link-local or unique-local destinations per source; NAT can merge many devices into one source and ARP or neighbor discovery is not observed (RFC 1918, RFC 6598, RFC 4193).',
    'DATA_EXFILTRATION': 'This detector sums reported bytes from an internal source to one public destination. Reported bytes include headers and retransmissions and do not reveal content (RFC 9293).',
    'BEACONING': 'This detector compares intervals between connection starts to one public address and port. NAT keep-alives, QUIC and TCP keep-alive timers can produce regular timing (RFC 4787, RFC 9000, RFC 9293).',
    'IOC_MATCH': 'An indicator matches an address, not an actor. Address reassignment, NAT and shared hosting make IP indicators decay quickly (RFC 4787).',
    'PORT_53_BURST': 'DNS can use UDP, TCP, TLS or HTTPS. Port 53 observations are not a count of parsed DNS questions (RFC 7766, RFC 7858, RFC 8484).',
    'NEW_DESTINATION_PORT': 'A transport port is not an application identity. QUIC uses UDP, while TLS protects application data (RFC 9000, RFC 8446).',
    'PROTOCOL_SHIFT': 'A TCP-to-UDP shift can reflect QUIC use; transport metadata alone cannot identify the application or establish the cause (RFC 9000).',
    'SERVICE_SHIFT': 'A sensor service label is an observation, not proof of an application. QUIC is a secure UDP-based transport (RFC 9000).',
}


def for_pattern(rule: str) -> str:
    return CONTEXT.get(rule, '')
