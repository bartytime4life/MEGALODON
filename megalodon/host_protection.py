"""Bounded operator policy for stateful protection of this Linux host.

Traffic history and model output never create service exceptions. This module
builds previews only; the separately authorized helper applies the fixed policy.
"""
from __future__ import annotations

from copy import deepcopy
from ipaddress import ip_network

LEASE_SECONDS = (900, 3600, 28800)
MAX_SERVICES = 8


def validate_policy(value):
    if type(value) is not dict or set(value) != {'services', 'duration_seconds'}:
        raise ValueError('Choose inbound services and a protection duration.')
    if type(value['duration_seconds']) is not int or value['duration_seconds'] not in LEASE_SECONDS:
        raise ValueError('Choose 15 minutes, 1 hour or 8 hours.')
    services = value['services']
    if type(services) is not list or len(services) > MAX_SERVICES:
        raise ValueError('Choose at most eight inbound service exceptions.')
    seen = set()
    for rule in services:
        if type(rule) is not dict or set(rule) != {'protocol', 'port', 'source'}:
            raise ValueError('Each service needs a protocol, port and client network.')
        if type(rule['protocol']) is not str or rule['protocol'] not in {'tcp', 'udp'}:
            raise ValueError('Choose TCP or UDP for each service.')
        if type(rule['port']) is not int or not 1 <= rule['port'] <= 65535:
            raise ValueError('Service ports must be integers from 1 to 65535.')
        if type(rule['source']) is not str or len(rule['source']) > 49:
            raise ValueError('Use a canonical client network in CIDR notation.')
        network = ip_network(rule['source'], strict=True)
        if str(network) != rule['source']:
            raise ValueError('Use a canonical client network in CIDR notation.')
        if network.network_address.is_multicast or network.network_address.is_loopback:
            raise ValueError('Use a unicast client network; loopback is already preserved.')
        if network.version == 6 and (network.network_address.ipv4_mapped or any(
                network.overlaps(ip_network(prefix)) for prefix in ('64:ff9b::/96', '64:ff9b:1::/48'))):
            # ::/0 is an explicit all-IPv6 exception, not an embedded-IPv4 alias.
            if network.prefixlen != 0:
                raise ValueError('Embedded IPv4 client ranges are not supported.')
        key = (rule['protocol'], rule['port'], rule['source'])
        if key in seen:
            raise ValueError('Remove duplicate inbound services.')
        seen.add(key)
    return deepcopy(value)


def preview_policy(policy):
    policy = validate_policy(policy)
    return dict(
        kind='host_protection', policy=policy,
        duration_seconds=policy['duration_seconds'],
        effect='Automatically drop unsolicited inbound traffic on this PC, except the services you explicitly allow.',
        preserved=['Loopback', 'Tracked established and related connections', 'Outbound connections and their replies',
                   'Essential ICMP errors, IPv6 neighbor discovery and DHCP client replies'],
        impact='New incoming remote desktop, SSH, file sharing, discovery and game connections need an explicit exception. Tracked established connections remain. An older untracked connection may need a service exception. Allowed services still need authentication and patching.',
        recovery='The kernel lease expires without the HUD. Remove protection ends only this managed policy early. Other firewall policies remain in force.',
    )
