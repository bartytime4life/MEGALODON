# Unambiguous JSONL evidence admission

A JSONL record must have one meaning before it reaches the detector or audit
store. The former decoder used Python's last-value-wins handling of duplicate
keys, and the domain projection ignored unknown top-level fields. For example,
two `src_ip` members could silently replace the first source address. This
change refuses ambiguous or unsupported input instead of choosing a value.

Allowed fields are `observed_at` (or legacy `timestamp`, never both), `src_ip`,
`dst_ip`, `protocol`, `src_port`, `dst_port`, `tcp_flags`, `dns_query_length`,
`byte_count`, `interface`, and `metadata`. Existing domain validation still
checks required addresses/time, ranges, flags and the closed metadata adapter.

Duplicate keys are rejected after JSON escape decoding, at every object level,
even if their values match. Unknown fields, including payload and command
extensions, are rejected. Numeric tokens must be nonnegative integers at most
9223372036854775807; floats, exponent forms, negative zero and non-finite
constants are not accepted. Field-specific limits can be smaller. The existing
domain handling of numeric strings is unchanged. The root plus its flat
metadata object or flags array may be at most two containers deep.

The 64 KiB line limit includes the newline and UTF-8 byte count. An API caller
can lower but cannot raise this cap. Blank lines and comments retain their
physical line numbers and the same size bound. Malformed Unicode is reported
as a capture error; decoder buffering means a decode failure identifies the
next attempted line, not necessarily the precise physical byte location.

On refusal, the CLI retains committed prefix events, records a failed run with
`CAPTURE_ERROR`, and emits its existing bounded diagnostic. The rejected record
and unread suffix produce no events, detections or actions. This does not make
whole-file ingestion atomic or attest the producer's truthfulness. Producers
that emitted extra fields, duplicate members, both timestamp aliases or numeric
floats must correct their export; they are intentionally no longer accepted.

## Evidence and source basis

This pass is based on main `caf7e4bd441ddd33facd2b7d406e4abe5e7e72c9`.
The supplied Advancement Blueprint sections 2–4 prioritize closed source
contracts and truthful atomic evidence. The Command Center Blueprint's input
boundary and read-model sections preserve those requirements before adding
integrations. The supplied generic Repository Research Analysis Framework is
a method reference, not evidence of this repository's implementation.

*Building Secure and Reliable Systems*, supplied PDF pp. 150–152, motivates
validation at the constructor/boundary before passing data onward. The incident
report motivates checking adjacent admission surfaces; this patch neither
reproduces that incident nor claims a demonstrated model escape. Python's
[JSON decoder documentation](https://docs.python.org/3/library/json.html#repeated-names-within-an-object)
confirms the default repeated-name behavior being replaced. The implementation
and synthetic fixtures are original; no book text or payload is redistributed.
