# Off-machine alerts

MEGALODON can forward new findings to a phone, a chat channel or a SIEM, so an
alert still reaches you when the monitored computer is the one under attack.
This is **off by default**. It applies to `megalodon run` and to the HUD's
managed capture.

## Configure

Add an `[alerts]` table and one or more destinations to the settings file used
by `megalodon run --config` or the HUD (usually
`~/.config/megalodon/settings.toml`):

```toml
[alerts]
enabled = true
min_severity = "HIGH"        # LOW, MEDIUM, HIGH or CRITICAL
detail = "standard"          # minimal, standard or full (see below)
sensor_name = "home-gateway" # default: this computer's host name
max_per_minute = 10          # per destination, 1-120

[[alerts.destination]]
name = "phone"
kind = "webhook"
format = "ntfy"              # json, slack, discord or ntfy
url_file = "~/.config/megalodon/alerts/ntfy.url"
# token_file = "~/.config/megalodon/alerts/ntfy.token"   # sent as Authorization: Bearer

[[alerts.destination]]
name = "siem"
kind = "syslog"
host = "192.168.1.20"
port = 514
protocol = "udp"             # udp or tcp
facility = "local0"
```

Webhook URLs usually contain a secret (a Slack or Discord token, an ntfy topic),
so they are never written in the settings file. Put each URL on one line in its
own file, readable only by you:

```bash
install -m 600 /dev/null ~/.config/megalodon/alerts/ntfy.url
```

```bash
echo 'https://ntfy.sh/your-private-topic' > ~/.config/megalodon/alerts/ntfy.url
```

Then send a labeled test alert to every destination:

```bash
megalodon alerts test --config ~/.config/megalodon/settings.toml
```

It prints each destination's result and exits 1 if any did not accept the
test. The test is a synthetic `LOW` notice that says no finding occurred.

### Formats

| `format` | Sends | Works with |
| --- | --- | --- |
| `json` | the `megalodon-alert-v1` record below | your own receiver, n8n, Home Assistant, SOAR intake |
| `slack` | `{"text": …}` with `<`, `>` and `&` escaped | Slack, Mattermost, Rocket.Chat incoming webhooks |
| `discord` | `{"content": …}` with all mentions disabled | Discord channel webhooks |
| `ntfy` | plain-text body; `Title`, `Priority` and `Tags` headers | ntfy.sh or a self-hosted ntfy (phone push) |

Syslog messages are RFC 5424 with structured data under
`megalodon@32473`, which uses the documentation example enterprise number
(RFC 5612). TCP uses RFC 6587 octet counting. The syslog priority follows the
finding: CRITICAL is `crit`, HIGH `err`, MEDIUM `warning` and LOW `notice`.

### What leaves the machine

| `detail` | Fields |
| --- | --- |
| `minimal` | sensor name, rule, severity, detection time, ATT&CK techniques, the rule's fixed summary |
| `standard` (default) | the above plus the source and destination addresses |
| `full` | the above plus the finding message, which can name a domain, server name or port |

Raw packets, payloads, stored evidence, file contents and the HUD's address
book are never sent. An alert carries `suppressed_before` when earlier findings
were held back by the rate limit, a full queue or a failed delivery. An
[evidence collection](evidence-collection.md) notice carries `digest`, the
bundle's manifest SHA-256, at every detail level and in every format.

## How delivery works

* **After saving, never before.** A finding is forwarded only after its audit
  bundle has been saved. A finding whose save fails is never sent, and a
  failed alert never changes or removes the saved finding.
* **Never in the way.** Each destination has its own background thread and a
  queue of at most 256 findings. Packet processing never waits for the
  network, and a dead SIEM does not hold back a phone push.
* **Bounded.** Each destination has a token-bucket rate limit
  (`max_per_minute`, with a burst of the same size). A delivery gets three
  attempts, 0, 2 and 8 seconds apart, each with a 5-second timeout. Findings
  beyond the limits are counted, not queued forever.
* **Short runs still deliver.** When `megalodon run` exits, it waits up to
  10 seconds for queued alerts.
* **HTTPS only.** Webhooks must use `https://`. Plain `http://` is accepted only
  for a literal loopback or private address, such as a self-hosted ntfy on your
  LAN. URLs with `user:password@` are refused. A redirect counts as a failure,
  so a secret URL is never forwarded to another host.
* **Secrets stay put.** URL and token files must be regular, single-line,
  owned by you and mode 600. Links, FIFOs and shared files are refused. Logs
  and `alerts test` report only the destination name and the error type,
  never the URL or token.
* **Refused at startup.** If a configured secret file is missing or unsafe,
  `megalodon run` and the HUD capture refuse to start rather than run without
  the alerts you expect.

## Limits

* Delivery is best effort and in memory. Queued alerts are lost if the process
  is killed, and there is no delivery receipt or acknowledgement. The local
  store remains the record. Review findings in the HUD.
* This notifier is separate from the draft
  [alert lifecycle contract](alert-lifecycle-contract.md). It has no
  acknowledgement, assignment or durable outbox, and it changes nothing that
  contract describes.
* Syslog over UDP can be lost or spoofed on the network, and there is no TLS
  syslog. Use TCP to a collector on a trusted network.
* An alert is a notice to look, not evidence of compromise and not authority
  to act. Rule severities are uncalibrated review signals (see
  [threat detection](threat-detection.md)).
* A destination provider (Slack, Discord, ntfy.sh) receives whatever `detail`
  you choose. Use `minimal` or a self-hosted receiver if that matters.
