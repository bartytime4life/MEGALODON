"""New USB devices, keyboards, network adapters, removable disks and Thunderbolt devices.

A keystroke-injection stick (BadUSB, Rubber Ducky) presents itself as a
keyboard. A rogue network implant presents a USB network adapter. A dropped
stick is mass storage. `megalodon devices` records the devices attached to
this machine and reports new ones (ATT&CK T1200, T1091, T1052, T1557).

Read-only; reads only /sys. Identifiers are vendor and product numbers,
names and serial numbers, which say what a device claims to be: a hostile
device can claim anything, but it must claim something new.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import time

SCHEMA = 'megalodon-device-watch-v1'
REPORT_SCHEMA = 'megalodon-device-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/devices.json'
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DEVICES = 4096
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

# USB interface classes (bInterfaceClass), by what they make a device able to do.
HID, STORAGE, COMMS, CDC_DATA, WIRELESS, VENDOR = '03', '08', '02', '0a', 'e0', 'ff'
RULES = {
    'NEW_USB_KEYBOARD': ('HIGH', ['T1200'], 'A new USB device that types: a keyboard interface. Keystroke-injection '
                                            'devices look like this, and so does a new keyboard.'),
    'NEW_NETWORK_ADAPTER': ('HIGH', ['T1200', 'T1557'], 'A new physical network adapter. A network implant plugged '
                                                        'into USB can reroute or watch this machine\'s traffic.'),
    'NEW_THUNDERBOLT_DEVICE': ('HIGH', ['T1200'], 'A new Thunderbolt device. Thunderbolt devices can read memory '
                                                  'directly unless the kernel\'s DMA protection blocks it.'),
    'NEW_USB_STORAGE': ('MEDIUM', ['T1091', 'T1052'], 'A new USB storage device: a way for files to come in or go '
                                                      'out.'),
    'NEW_REMOVABLE_DISK': ('MEDIUM', ['T1091', 'T1052'], 'A new removable disk.'),
    'DEVICE_GAINED_FUNCTIONS': ('HIGH', ['T1200'], 'A known USB device now offers interfaces it did not have, such '
                                                   'as a "storage stick" that can also type.'),
    'NEW_USB_DEVICE': ('LOW', ['T1200'], 'A new USB device of another kind.'),
}


class DeviceError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _text(path, limit=256):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace').strip()
    except OSError:
        return ''


def _usb(sysfs):
    devices, base = {}, Path(sysfs, 'bus/usb/devices')
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return devices
    for name in entries[:MAX_DEVICES]:
        folder = base / name
        vendor = _text(folder / 'idVendor')
        if not vendor or ':' in name:       # interfaces are 1-2:1.0; devices have idVendor
            continue
        interfaces = []
        for item in sorted(entries):
            if item.startswith(name + ':'):
                interface = base / item
                interfaces.append('/'.join((_text(interface / 'bInterfaceClass'),
                                            _text(interface / 'bInterfaceSubClass'),
                                            _text(interface / 'bInterfaceProtocol'))))
        product = _text(folder / 'idProduct')
        serial = _text(folder / 'serial')
        label = ' '.join(p for p in (_text(folder / 'manufacturer'), _text(folder / 'product')) if p)
        # A device is known by what it says it is, not by the port it is plugged into.
        key = f'usb:{vendor}:{product}:{serial or label or "-"}'
        entry = devices.setdefault(key, dict(kind='usb', vendor=vendor, product=product, serial=serial, name=label,
                                             device_class=_text(folder / 'bDeviceClass'), ports=[], interfaces=[]))
        entry['ports'] = sorted(set(entry['ports']) | {name})
        entry['interfaces'] = sorted(set(entry['interfaces']) | set(interfaces))
    return devices


def _network(sysfs):
    devices, base = {}, Path(sysfs, 'class/net')
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return devices
    for name in names[:MAX_DEVICES]:
        try:
            target = os.path.realpath(base / name / 'device')
        except OSError:
            continue
        # Virtual adapters (bridges, veth, tunnels) come and go with containers and VPNs; physical ones are hardware.
        if not os.path.exists(base / name / 'device') or '/virtual/' in target:
            continue
        address = _text(base / name / 'address')
        bus = 'usb' if '/usb' in target else ('pci' if '/pci' in target else 'other')
        devices[f'net:{address or name}'] = dict(kind='network', interface=name, address=address, bus=bus,
                                                 driver=os.path.basename(os.path.realpath(base / name / 'device/driver'))
                                                 if os.path.exists(base / name / 'device/driver') else '')
    return devices


def _disks(sysfs):
    devices, base = {}, Path(sysfs, 'block')
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return devices
    for name in names[:MAX_DEVICES]:
        target = os.path.realpath(base / name)
        removable = _text(base / name / 'removable') == '1'
        if not (removable or '/usb' in target):
            continue
        model = ' '.join(p for p in (_text(base / name / 'device/vendor'), _text(base / name / 'device/model')) if p)
        serial = _text(base / name / 'device/serial') or _text(base / name / 'device/wwid')
        devices[f'disk:{model or name}:{serial or "-"}'] = dict(kind='disk', name=name, model=model, serial=serial,
                                                               removable=removable, usb='/usb' in target)
    return devices


def _thunderbolt(sysfs):
    devices, base = {}, Path(sysfs, 'bus/thunderbolt/devices')
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return devices
    for name in names[:MAX_DEVICES]:
        folder = base / name
        unique = _text(folder / 'unique_id')
        if not unique:
            continue
        devices[f'thunderbolt:{unique}'] = dict(kind='thunderbolt', name=_text(folder / 'device_name'),
                                                vendor=_text(folder / 'vendor_name'),
                                                authorized=_text(folder / 'authorized'))
    return devices


def snapshot(*, sysfs='/sys'):
    devices = {}
    for reader in (_usb, _network, _disks, _thunderbolt):
        devices.update(reader(sysfs))
    gaps = []
    if not os.path.isdir(os.path.join(sysfs, 'bus/usb')):
        gaps.append('this machine has no USB bus in /sys')
    return dict(devices=devices, gaps=gaps)


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.devices-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise DeviceError(f'no device baseline at {path}; run megalodon devices baseline') from None
    except OSError as exc:
        raise DeviceError(f'device baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise DeviceError(f'device baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise DeviceError('device baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise DeviceError('device baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('devices')) is not dict:
        raise DeviceError('device baseline has an unsupported format')
    return value


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise DeviceError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), **state))
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), devices=len(state['devices']),
                gaps=state['gaps'])


def _classes(entry):
    return {i.split('/')[0] for i in entry.get('interfaces', [])}


def _keyboard(entry):
    # HID boot keyboards are 03/01/01; many injection devices report 03/00/00 and type anyway, so any HID
    # interface on a device that is not a plain mouse (03/01/02) counts.
    hid = [i for i in entry.get('interfaces', []) if i.startswith(HID + '/')]
    return bool(hid) and any(i != '03/01/02' for i in hid)


def _finding(rule, key, entry, detail):
    severity, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=techniques, device=key, detail=detail, summary=summary,
                entry=entry)


def _describe(entry):
    if entry['kind'] == 'usb':
        return f"{entry.get('name') or 'unnamed device'} ({entry['vendor']}:{entry['product']}) on port " \
               f"{', '.join(entry.get('ports', [])) or '?'}"
    if entry['kind'] == 'network':
        return f"{entry['interface']} ({entry.get('address') or 'no address'}, {entry.get('bus')})"
    if entry['kind'] == 'disk':
        return f"{entry.get('model') or entry['name']} ({entry['name']})"
    return f"{entry.get('vendor', '')} {entry.get('name', '')}".strip()


def compare(old, new):
    findings, removed = [], sorted(set(old) - set(new))
    for key in sorted(set(new)):
        entry = new[key]
        before = old.get(key)
        if before is None:
            if entry['kind'] == 'usb':
                classes = _classes(entry)
                if _keyboard(entry):
                    rule = 'NEW_USB_KEYBOARD'
                elif STORAGE in classes:
                    rule = 'NEW_USB_STORAGE'
                elif classes & {COMMS, CDC_DATA, WIRELESS}:
                    rule = 'NEW_NETWORK_ADAPTER'   # RNDIS / CDC Ethernet: how USB network implants appear
                else:
                    rule = 'NEW_USB_DEVICE'
            else:
                rule = {'network': 'NEW_NETWORK_ADAPTER', 'disk': 'NEW_REMOVABLE_DISK',
                        'thunderbolt': 'NEW_THUNDERBOLT_DEVICE'}[entry['kind']]
            findings.append(_finding(rule, key, entry, f'new: {_describe(entry)}'))
        elif entry['kind'] == 'usb':
            gained = sorted(set(entry.get('interfaces', [])) - set(before.get('interfaces', [])))
            if gained:
                findings.append(_finding('DEVICE_GAINED_FUNCTIONS', key, entry,
                                         f"{_describe(entry)} now also offers {', '.join(gained)}"))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['device']))
    return findings, removed


def check(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest)
    new = snapshot(**options)
    findings, removed = compare(old['devices'], new['devices'])
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings, removed=removed,
                gaps=new['gaps'], note='Review each device; accept records the reviewed state.')


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)
    return dict(baseline(manifest, replace=True, **options), action='accept')


def watch(manifest=DEFAULT_MANIFEST, emit=print, *, interval=2.0, stop=None, **options):
    """Check every interval; each new finding is emitted once (until it is accepted)."""
    reported = set()
    while stop is None or not stop.is_set():
        report = check(manifest, **options)
        for found in report['findings']:
            mark = (found['rule_id'], found['device'], tuple(found['entry'].get('interfaces', [])))
            if mark not in reported:
                reported.add(mark)
                emit(found)
        if stop is not None:
            stop.wait(interval)
        else:
            time.sleep(interval)
