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
    'DECOY_TOUCH': 'A decoy is a port or unassigned address that no service uses, so contact implies discovery. Address spoofing, broadcast-to-unicast relays and stale ARP or DNS entries can still produce stray packets (RFC 1918, RFC 826).',
    'DGA_DOMAIN': 'This detector scores the spelling of a queried name (entropy, length, digit mixing, consonant runs, stacked or deep labels). A name is not an identity; DNS-over-HTTPS and DNS-over-TLS queries are invisible to it (RFC 8484, RFC 7858).',
    'DNS_TUNNEL_CHURN': 'This detector counts distinct subdomains per source under one registrable domain, approximated without a public-suffix list. Resolver caching hides repeats, and encrypted DNS is invisible to it (RFC 1035, RFC 8484).',
    'ARP_SPOOFING': 'This detector compares each IPv4 address with the hardware address that last answered for it. ARP has no authentication, so any LAN host can claim any address; failover and virtualization can also move an address (RFC 826, RFC 5227).',
    'ROGUE_DHCP': 'This detector compares the server identifier in DHCP offers and acknowledgements, or the sender of DHCPv6 advertisements and replies, with the expected or recently seen servers of the same address family. DHCP has no server authentication, and relays forward replies from servers elsewhere (RFC 2131, RFC 3046, RFC 8415).',
    'NDP_SPOOFING': 'This detector compares each IPv6 address with the hardware address that last claimed it in a neighbour solicitation, neighbour advertisement or router advertisement. Neighbour discovery has no authentication unless SEND is deployed, which it rarely is; failover and virtualization can also move an address (RFC 4861, RFC 3971).',
    'ROGUE_IPV6_ROUTER': 'This detector compares the sender of each IPv6 router advertisement with the expected or recently seen routers. Any host on the link can advertise itself as a router unless the switch filters advertisements (RA Guard); a router lifetime of zero withdraws a default route instead (RFC 4861, RFC 6105).',
    'DNS_BYPASS': 'This detector compares the destination of DNS (port 53), DNS over TLS or QUIC (port 853) and HTTPS to well-known public resolvers with the resolvers this network should use. DNS over HTTPS to an unlisted provider looks like ordinary HTTPS and is not seen (RFC 7858, RFC 8484, RFC 9250).',
    'TLS_WITHOUT_SNI': 'This detector flags a TLS ClientHello without a server_name extension from an internal host to a public address. SNI is optional, and Encrypted Client Hello hides the real name (RFC 6066, RFC 8446).',
    'IOC_MATCH': 'An indicator matches an address, not an actor. Address reassignment, NAT and shared hosting make IP indicators decay quickly (RFC 4787).',
    'PORT_53_BURST': 'DNS can use UDP, TCP, TLS or HTTPS. Port 53 observations are not a count of parsed DNS questions (RFC 7766, RFC 7858, RFC 8484).',
    'NEW_DESTINATION_PORT': 'A transport port is not an application identity. QUIC uses UDP, while TLS protects application data (RFC 9000, RFC 8446).',
    'PROTOCOL_SHIFT': 'A TCP-to-UDP shift can reflect QUIC use; transport metadata alone cannot identify the application or establish the cause (RFC 9000).',
    'SERVICE_SHIFT': 'A sensor service label is an observation, not proof of an application. QUIC is a secure UDP-based transport (RFC 9000).',
}


def for_pattern(rule: str) -> str:
    return CONTEXT.get(rule, '')
