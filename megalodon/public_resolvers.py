"""Well-known public DNS resolvers, for recognizing DNS over HTTPS.

DNS over HTTPS looks like any other HTTPS connection on port 443, so it is
recognized by where it goes: the anycast addresses of well-known public
resolvers, or, with TLS server names opted in, their DoH host names. These
addresses serve DNS and nothing else, so HTTPS to them is DNS.

The list is deliberately short and limited to resolvers that publish these
addresses and names for DNS. A provider that is missing here can still be
caught on ports 53 and 853, or added to the IOC watchlist.
"""
from __future__ import annotations

import ipaddress

# provider -> (addresses or networks, DoH host names; subdomains match too)
PROVIDERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Cloudflare": (
        ("1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
         "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112",
         "2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003"),
        ("cloudflare-dns.com", "one.one.one.one"),
    ),
    "Google": (
        ("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
        ("dns.google", "dns.google.com"),
    ),
    "Quad9": (
        ("9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
         "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11"),
        ("dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net"),
    ),
    "OpenDNS": (
        ("208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
         "2620:119:35::35", "2620:119:53::53"),
        ("doh.opendns.com", "doh.familyshield.opendns.com"),
    ),
    "AdGuard": (
        ("94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
         "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
        ("dns.adguard-dns.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com", "dns.adguard.com"),
    ),
    "CleanBrowsing": (
        ("185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11",
         "185.228.168.168", "185.228.169.168"),
        ("doh.cleanbrowsing.org",),
    ),
    "NextDNS": (
        ("45.90.28.0/24", "45.90.30.0/24"),
        ("dns.nextdns.io",),
    ),
    "Mullvad": (
        ("194.242.2.2", "194.242.2.3", "194.242.2.4"),
        ("dns.mullvad.net",),
    ),
}

_NETWORKS = tuple(
    (ipaddress.ip_network(address), provider)
    for provider, (addresses, _) in PROVIDERS.items() for address in addresses
)
_NAMES = tuple((name, provider) for provider, (_, names) in PROVIDERS.items() for name in names)


def provider_for_address(address: str) -> str | None:
    """The provider whose published resolver address this is, else None."""
    parsed = ipaddress.ip_address(address)
    for network, provider in _NETWORKS:
        if network.version == parsed.version and parsed in network:
            return provider
    return None


def provider_for_name(name: str | None) -> str | None:
    """The provider whose DoH host name (or a subdomain of it) this is, else None."""
    if not name:
        return None
    name = name.lower().rstrip(".")
    for suffix, provider in _NAMES:
        if name == suffix or name.endswith("." + suffix):
            return provider
    return None
