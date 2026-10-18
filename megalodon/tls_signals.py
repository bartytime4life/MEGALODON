"""Review-only TLS handshake signals from sensor metadata. Nothing is decrypted or blocked.

The sensor reports a handshake's protocol version and, when the certificate is
visible, its validity dates and subject/issuer names. These signals describe
that metadata only. Routers, printers and lab devices commonly use
self-signed certificates, and TLS 1.3 hides certificates from passive sensors,
so a signal is a reason to look, never proof of interception or intent.
Certificate names are compared, never stored.
"""
from datetime import datetime, timezone
import re

SCHEMA = 'megalodon-tls-review-v1'
SOURCE = 'Suricata EVE TLS (sensor context)'
MAX_PER_PEER = 2
MAX_SNAPSHOT_RECORDS = 32
ATTACK = ('T1573', 'T1557')
_VERSION = re.compile(r'(?:SSLv[23]|TLS ?1\.[0-3]|TLSv1(?:\.[0-3])?|UNDETERMINED)')
_LEGACY = {'SSLv2', 'SSLv3', 'TLS 1.0', 'TLS1.0', 'TLSv1', 'TLSv1.0', 'TLS 1.1', 'TLS1.1', 'TLSv1.1'}
_TIME = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
MAX_NAME_CHARS = 1024


def _time(value):
    """Suricata writes certificate times as naive UTC timestamps."""
    if type(value) is not str or not _TIME.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def assess(tls, observed):
    """Return one bounded review record for a handshake, or None without signals.

    `tls` is an EVE `tls` object and `observed` the aware event time.
    """
    if not isinstance(tls, dict) or not isinstance(observed, datetime) or observed.tzinfo is None:
        return None
    version = tls.get('version')
    version = version if type(version) is str and _VERSION.fullmatch(version) else None
    signals = {}
    if version in _LEGACY:
        signals['legacy_protocol'] = f'The handshake used {version}, which is deprecated (RFC 8996).'
    not_after, not_before = _time(tls.get('notafter')), _time(tls.get('notbefore'))
    if not_after is not None and observed > not_after:
        signals['expired_certificate'] = 'The server certificate had expired when the handshake was observed.'
    if not_before is not None and observed < not_before:
        signals['not_yet_valid_certificate'] = 'The server certificate was not yet valid when the handshake was observed.'
    subject, issuer = tls.get('subject'), tls.get('issuerdn')
    if (type(subject) is str and type(issuer) is str and 0 < len(subject.strip()) <= MAX_NAME_CHARS
            and subject.strip() == issuer.strip()):
        signals['self_signed_certificate'] = 'The certificate names itself as its issuer (self-signed).'
    if not signals:
        return None
    # A self-signed certificate alone is routine for local devices; the rest merit review.
    level = 'note' if set(signals) == {'self_signed_certificate'} else 'review'
    return dict(schema=SCHEMA, level=level, version=version, attack=list(ATTACK),
                signals=[dict(id=key, detail=detail) for key, detail in signals.items()],
                context=['Routers, printers and lab devices often use self-signed certificates.',
                         'A TLS signal is not evidence of interception, malware or intent.'],
                observed_at=observed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
                source=SOURCE, action_status='not_attempted')


def add(records, record):
    """Append a record unless the same signals were already kept for this peer."""
    if record is None or len(records) >= MAX_PER_PEER:
        return
    key = (record['version'], tuple(s['id'] for s in record['signals']))
    if all((r['version'], tuple(s['id'] for s in r['signals'])) != key for r in records):
        records.append(record)
