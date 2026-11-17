# Protect the PC running MEGALODON

This source candidate adds an explicit, time-limited Linux host firewall policy
in **Overview → Control incoming connections**. Once applied, the kernel drops
unsolicited inbound traffic automatically. It does not wait for a model, a
packet-capture process, an IP reputation service or the dashboard to classify an
attacker. Repeated probes of unapproved services continue to hit the same drop
rule, without allocating a new record or a per-attacker block entry.

Desired access is defined by the operator's service policy and Linux connection
tracking. Frequency, a familiar hostname, an observed port or AI advice cannot
authorize a connection. A permitted connection is not a safety verdict.

## Use the workflow

1. Start a reviewed checkout on this Linux PC and open the local HUD. The
   installed application does not change merely because this branch exists.
2. Expand **Choose allowed services and preview protection**. With no exceptions,
   the policy allows no new inbound service connections. For remote access,
   sharing or another incoming service, add its protocol, port and allowed
   client network. Use a single client's `/32` (IPv4) or `/128` (IPv6) when
   practical. The form supports at most eight explicit exceptions.
3. Start with **15 minutes**. Longer choices are one hour and eight hours.
   Select **Preview host protection**, read the exact service list and impact,
   then **Confirm protection on this PC**. The system authorization prompt is a
   separate step. A preview lasts 60 seconds and can be used only once.
4. Read **Last verified active**, its verification time, lease estimate and
   allowed services. **Verify protection with OS authorization** performs a
   fresh kernel inspection and returns packet counters. Ordinary page refresh
   reads the saved outcome; it does not ask for elevated privileges.
5. To renew, explicitly copy the last verified policy into the form, review it,
   and create a new preview. Renewal atomically replaces this managed policy,
   resets its counters and starts a new finite lease. **Remove this protection**
   removes only the validated MEGALODON host table.

Changing a service or duration invalidates the visible preview, including while
a preview request is running. Old successes and failures cannot authorize the
new form. A failed status request clears displayed authority and counters.

## What is preserved

- Loopback traffic, including the local HUD.
- Connections already classified as established or related by Linux conntrack.
- New outbound connections and their replies.
- ICMP error messages needed for routing and path MTU discovery.
- IPv6 router/neighbor discovery with hop limit 255, and link-local multicast
  listener queries with hop limit 1.
- DHCPv4 server-port 67 to client-port 68 replies, and link-local DHCPv6
  server-port 547 to client-port 546 replies.
- The exact inbound TCP/UDP services and client CIDRs in the approved policy.

**First activation:** a socket opened before connection tracking was active
may not be recognized as established. Give required incoming SSH, remote
desktop or other administrative access an explicit service exception before
activation. Do not infer this exception from a prior successful connection.

All other inbound packets are dropped while the lease is active. Existing host
firewall restrictions still apply: an accept in this table does not override a
drop in another table. There are no output or forwarding chains, router
configuration changes, firewall flushes, persistent boot rules or unattended
lease renewals in this workflow.

## Recovery and evidence

The isolated `inet megalodon_host_guard` table contains a two-element timed
`nf_proto` set. Only IPv4/IPv6 families whose lease element is present enter the
filter chain; the base chain otherwise accepts. Expiry therefore stops this
policy even when the HUD or helper has exited. The displayed expiry is an
estimate from the last kernel readback, not a continuous ruleset inspection.
After sleep or a clock change, verify the kernel state again. Elapsed UI time
never becomes a new claim of kernel inactivity.

Every action gets a private intent receipt before helper execution and an
outcome afterward. An interrupted apply/check/remove is **Needs verification**
after restart. Four recent host-action receipts are retained in the replay
selection independently of the short per-IP containment window. GET never
replays a mutation. Removal remains available even when there is no recorded
active lease, so an authorized operator can reconcile an uncertain outcome.
Audit-storage failure stops helper execution.

If the UI is unavailable, expiry provides the bounded recovery path. From a
local administrative console, inspect `nft -j list table inet
megalodon_host_guard` before manual recovery. Removing exactly this table with
`nft delete table inet megalodon_host_guard` ends only this policy; never flush
the host ruleset. Manual administrator recovery is outside the HUD receipt
workflow. A changed/foreign managed table makes the application refuse both
replacement and removal, so review the conflict at the console.

The helper requires OS authorization, uses a fixed root-owned regular
`/usr/sbin/nft` executable with a fixed environment and working directory,
serializes operations with a private root lock, caps subprocess output and
runtime, validates every rule on readback, and uses an atomic table replacement.
The HTTP API retains local Host/sign-in/Origin/token checks, a closed action
schema, duplicate-key rejection and a 2 KiB body bound. A model never selects
commands or supplies an apply action.

## Coverage limits and next work

This is **host input protection**, not an intrusion-prevention verdict. It does
not protect other PCs, routed traffic, containers/VMs on forwarding paths, or
attacks inside allowed services or existing sessions. It does not inspect TLS
payloads, distinguish human from AI attacks, undo a compromise, block malicious
outbound activity, patch applications or authenticate an allowed client. Keep
service authentication and patching in place. There is no field false-positive
rate or measured attack-prevention claim.

The next independent defense work should qualify live sensor inputs, correlate
repeated application/authentication failures with explicit service policy, and
validate any per-service temporary response in replay before adding authority.
Do not promote inferred intent, an LLM response or a raw SYN count to automatic
whole-address blocking; spoofed sources and shared services make that unsafe.

## Validation

`tests/test_host_protection.py` covers both policy validators, no-effect previews,
single-use/expired/cross-action previews, intent-before-execution, ambiguous
outcomes, restart, no privileged GET, strict helper output, foreign table refusal,
executable substitution and the real HTTP boundary.

The native harness requires **both a fresh user namespace and a fresh network
namespace**, identified against the parent. It creates only isolated veth
interfaces and synthetic peers:

```bash
MEGALODON_TEST_PARENT_NET="$(readlink /proc/self/ns/net)" \
  unshare --user --map-root-user --net \
  .venv312/bin/python tests/host_protection_native.py
```

It verifies actual IPv4/IPv6 TCP/UDP drops and allowed services, tracked sessions,
outbound replies, loopback, DHCPv4 scoping, real counters, expiry without a HUD,
removal, conflict refusal and preservation of an unrelated table. Only the test
harness shortens lease elements to exercise expiry. User-namespace UID mapping
requires bypassing executable ownership **in this harness only**; separate
negative unit checks cover that production validation. This is not production
installation or full native OS-authorization/lock acceptance.

`tests/browser_host_protection.py OUTPUT_DIRECTORY` exercises the shipped
component in installed Chrome using synthetic intercepted HTTP replies. It
checks keyboard confirmation, form/preview binding, explicit policy reuse,
320/390-pixel reflow, expiry and unavailable-state recovery. It never invokes
nftables. Rendered component acceptance is separate from installed HUD and
whole-application browser acceptance.

The browser acceptance workflow also runs this control journey and retains its
synthetic screenshots. The separate **Host protection packet acceptance** job
runs the native harness in fresh namespaces on Ubuntu and retains its result;
it never targets the runner's parent network namespace.

The stateful rules and lease semantics follow the primary
[nftables reference](https://www.netfilter.org/projects/nftables/manpage.html)
and [element timeout documentation](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts).
