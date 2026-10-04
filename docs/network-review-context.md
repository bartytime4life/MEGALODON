# Networking context for local AI reviews

The local model receives one short, fixed networking cue when it explains a
matching, evidence-backed review. This is prompt context, not model weight
training or an added detector. The selected Ollama model remains unchanged.
The cue is skipped if it would exceed the existing 4 KiB prompt bound. Model
output remains advice with the existing citation, workflow, and approval checks.

The cues address common errors in metadata interpretation:

| Review topic | Reviewed source | Limit conveyed to the model |
| --- | --- | --- |
| TCP port scans | [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) | The detector counts distinct destination ports per source across TCP packets, regardless of SYN flags. It does not group by destination host. Repeated packets to one port do not increase the count; intent and completed connections remain unproven. |
| SYN bursts | [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) | SYN retransmission means packet counts need not equal unique attempts, completed connections or resource exhaustion. |
| NAT and endpoint identity | [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787.html) | An observed translated tuple does not by itself identify one internal device. General observation does not establish that translation occurred. |
| Long DNS queries | [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html), [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html), [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) | The detector requires `dns_query_length` on a DNS or UDP event, without a destination-port condition. Length alone does not prove tunneling, reveal query content or cover all resolver activity. |
| Port-53 bursts | [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html), [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html), [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) | Port 53 observations are not parsed query counts or complete resolver coverage. |
| Application inference | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) | QUIC uses UDP and TLS protects application data; transport ports and sensor labels do not prove application identity. |

Detector-specific descriptions above are checked against local code; the RFCs
provide protocol background rather than evidence for a particular finding.
Unknown or unmapped rules receive no cue. RFC identifiers in a cue do not become
validated evidence citations in the returned model response.

The fixed cues do not fetch these documents at runtime, send private traffic
to a publisher, grant a model tools, or change host settings. Expanding the
reference library or the reviewed cue set requires source and test review.
