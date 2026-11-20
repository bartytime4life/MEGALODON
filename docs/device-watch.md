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
* **`watch`** listens for the kernel's device events and checks as soon as
  a device is added, and every `--interval` seconds (default 2) regardless.
  It prints each new device once per plug-in, as a JSON line. A device
  unplugged and plugged in again is printed again. `--poll` checks only every
  interval. Where the kernel's events cannot be heard, as in some sandboxes,
  it polls and says so when it starts. With `--respond`, each new device is
  decided and carried out at once: see [cut it off at once](#cut-it-off-at-once).
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

## Cut it off at once

A keystroke-injection device types within a second or two of being plugged
in, and a check every few minutes is too late for it. The scheduled
`megalodon-devices` service runs `devices watch --alert --respond`, which
hears the device arrive. On this machine, a real kernel event reached a
finding in about 50 ms: most of that is a short pause for the device's
interfaces to appear. The decision and the cut-off follow at once. That is
fast, not instant: some keystrokes may still get through before the device
is cut off.

1. Each USB finding names its `targets`: `PORT#NUMBER@usb:VENDOR:PRODUCT:SERIAL`.
   The number is the one the kernel gave this plug-in, so the target is one
   plug-in of one device, as a PID with its start time is one process.
2. The [response engine](response-engine.md)'s `new-hardware` playbook plans
   `block_device` for a new USB keyboard, USB network adapter, or a known
   device that gained functions, and sends a notice. A built-in network
   adapter or a Thunderbolt device is reported only: it has no USB port to
   cut off.
3. [Enforcement](enforcement.md) carries it out only if its policy is on and
   lists `block_device` and `new-hardware`. It checks that the same plug-in
   is still on that port, then writes `0` to the device's `authorized` file
   in `/sys`. The kernel lets go of its drivers: it cannot type, store or
   carry traffic. It stays attached, so you can see what it was.
4. To let a device you plugged in on purpose work:

   ```bash
   megalodon enforce undo ID
   ```

   ```bash
   megalodon devices accept
   ```

Guards:

* **Never the only keyboard.** A new keyboard is not cut off when no other
  keyboard is attached, counting built-in and Bluetooth keyboards. You may
  have just plugged it in to work with. It is reported, and the refusal is
  recorded with that reason. On a server with no keyboard at all, a new
  keyboard is reported but not cut off.
* **Never a device in the baseline,** because only new devices are findings.
  A device you already had that now also types is the exception: that is
  `DEVICE_GAINED_FUNCTIONS`.
* **Plugged in again, decided again.** A device cut off and plugged in again
  is a new plug-in. The kernel lets it work by default, and the watch decides
  it again. Undo after it was unplugged has nothing to let back, and says
  done.

## Limits

* **A device says what it is.** All identifiers are what the device reports,
  and a hostile device can copy a known keyboard's vendor, product and
  serial numbers. A copy of a device you already have is not new.
* **It cuts off after, not before.** With `--respond`, a new device is cut
  off moments after it is plugged in, not before it works. Keystrokes typed
  in that time get through. Keeping every new device off until you allow it
  needs a policy enforced by the kernel, such as USBGuard.
* **Between checks.** `check` sees what is attached when it runs. With the
  kernel's events, `watch` checks on each one. Polling, a device plugged in
  and removed between two checks is missed.
* **Root is needed to cut a device off.** Writing to `/sys` needs root, as
  the scheduled system service runs.
* **Linux only.** Devices are read from `/sys`.
