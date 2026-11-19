# Device watch

Physical access attacks plug something in:
- a keystroke-injection stick that presents itself as a keyboard and types
  commands faster than anyone can read them;
- a network implant that presents a USB network adapter and reroutes
  traffic;
- a stick left in a car park for someone to try;
- a Thunderbolt device that can read memory directly.

`megalodon devices` records what is attached to this machine and reports
what is new (ATT&CK T1200, T1091, T1052, T1557).

```bash
megalodon devices baseline
```

```bash
megalodon devices check
```

```bash
megalodon devices watch
```

```bash
megalodon devices accept
```

* **`baseline`** records the attached USB devices, physical network
  adapters, removable and USB disks and Thunderbolt devices in
  `~/.config/megalodon/devices.json` (mode 600).
* **`check`** reports new devices, most severe first. It exits 1 on findings
  and 2 on an error. Devices that were removed are listed under `removed`
  and are not findings.
* **`watch`** checks every `--interval` seconds (default 2) and prints each
  new device once, as a JSON line.
* **`accept`** records the current devices once you have reviewed them, for
  example after plugging in a new keyboard on purpose.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The
[response engine](response-engine.md) reads `check` on every pass and
notifies you of HIGH findings; only you know whether you plugged it in.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `NEW_USB_KEYBOARD` | HIGH | A new USB device with a keyboard or other typing (HID) interface. Mice alone are not counted. |
| `NEW_NETWORK_ADAPTER` | HIGH | A new physical network adapter, or a new USB device with a network interface (RNDIS, CDC Ethernet, wireless) |
| `NEW_THUNDERBOLT_DEVICE` | HIGH | A new Thunderbolt device |
| `DEVICE_GAINED_FUNCTIONS` | HIGH | A known USB device now offers interfaces it did not have, such as a "storage stick" that can now type |
| `NEW_USB_STORAGE` | MEDIUM | A new USB storage device |
| `NEW_REMOVABLE_DISK` | MEDIUM | A new removable or USB disk |
| `NEW_USB_DEVICE` | LOW | Any other new USB device |

A device that offers both storage and a keyboard, as many injection tools
do, is reported as a keyboard.

A USB device is known by its vendor and product numbers and its serial
number, or its name when it has none, not by the port it is plugged into.
Moving a known device to another port is not a finding. Virtual network
adapters (bridges, `veth`, tunnels) come and go with containers and VPNs,
and are left out.

## Limits

* **A device says what it is.** All identifiers are what the device reports,
  and a hostile device can copy a known keyboard's vendor, product and
  serial numbers. A copy of a device you already have is not new.
* **It reports, it does not block.** The device is already working when it
  is reported, and an injection stick types in seconds. Blocking new
  devices until you allow them needs a policy enforced by the kernel, such
  as USBGuard.
* **Between checks.** `check` sees what is attached when it runs. A device
  plugged in and removed between two `watch` checks is missed.
* **Linux only.** Devices are read from `/sys`.
