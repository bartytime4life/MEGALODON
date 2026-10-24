"""Bounded local geographic context for a retained endpoint, never an origin claim."""
from ipaddress import ip_address
import math

from .address_investigation import _stamp, _text

SCHEMA = 'megalodon-address-location-v1'


def project(endpoint, *, snapshot_at, capture_state, geography_context=None):
    address = ip_address(endpoint['ip'])
    value = endpoint.get('location')
    location = None
    local = endpoint.get('local')
    location_role = 'local_exit_anchor' if local is True else 'observed_network_endpoint'
    role_valid = type(local) is bool and endpoint.get('location_role') == location_role
    public = (address.is_global and not address.is_multicast and not address.is_reserved
              and getattr(address, 'ipv4_mapped', None) is None)
    if role_valid and local is False and public and type(value) is dict and value.get('approximate') is True:
        lat, lon = value.get('latitude'), value.get('longitude')
        label, source = _text(value.get('label'), 160), _text(value.get('source'), 128)
        if (type(lat) in (int, float) and type(lon) in (int, float)
                and math.isfinite(lat) and math.isfinite(lon)
                and -90 <= lat <= 90 and -180 <= lon <= 180 and label and source):
            radius = value.get('accuracy_radius_km')
            if type(radius) not in (int, float) or not math.isfinite(radius) or not 0 < radius <= 20000:
                radius = None
            country = value.get('country')
            if type(country) is not str or len(country) != 2 or not country.isascii() or not country.isalpha():
                country = None
            context = geography_context or {}
            same_source = context.get('source') == source
            location = dict(latitude=lat, longitude=lon, label=label, source=source,
                            country=country.upper() if country else None, approximate=True,
                            accuracy_radius_km=radius,
                            database_build_at=_stamp(context.get('build_date')) if same_source else None,
                            database_downloaded_at=_stamp(context.get('updated_at')) if same_source else None)
    return dict(schema=SCHEMA, observed_address=str(address), snapshot_at=snapshot_at,
                first_seen=_stamp(endpoint.get('first_seen')), last_seen=_stamp(endpoint.get('last_seen')),
                capture_state=capture_state, status='mapped' if location else 'unmapped', location=location,
                location_role=location_role, original_address=None, person_identity=None,
                physical_address=None, network_access_performed=False, action_authority='none')
