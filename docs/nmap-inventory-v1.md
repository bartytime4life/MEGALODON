# Completed Nmap inventory profile v1

The optional `megalodon.nmap_inventory` command reads one completed report from
stdin and prints a `megalodon-nmap-inventory-v1` JSON summary. It uses Python's
standard-library Expat parser, adds no dependency and never invokes Nmap. The
same summary can be loaded into the local HUD or hosted console's Network
inventory panel. Neither page uploads the summary, fetches another source,
persists it, or mixes it with traffic rates or detection severity.

## Operator flow

In the updated MEGALODON Python environment, on Linux:

```sh
umask 077
python -m megalodon.nmap_inventory < completed-report.xml > inventory-summary.json
```

Choose an existing report you are authorized to review. A failed command returns
1, writes a fixed diagnostic to stderr, and emits no JSON. Shell redirection may
create/truncate the output before that failure. Keep input/output separate and
use a new output filename. File selection and permissions belong to the shell;
the importer does not open paths, repair permissions or certify input provenance.
Native Windows shell/ACL acceptance is still unproved; the catalog says
`evaluation_only` for Windows and `optional` for Linux.

Load the resulting JSON in the Network inventory panel. Clear removes the held
view. Invalid imports preserve the previous dated view; an older pending read
cannot restore data after Clear or supersede a newer selection.

## Accepted producer projection

Nmap's [XML guide](https://nmap.org/book/output-formats-xml-output.html) and
[DTD documentation](https://nmap.org/book/nmap-dtd.html) describe the fields used
here. This is a bounded projection, not full DTD validation or certification of
every Nmap release. Admission requires root `nmaprun`, `scanner=nmap`, numeric
`version=7.x`, `xmloutputversion=1.05`, integer start/end UTC epoch seconds and
one `runstats` with `finished exit=success` and coherent host totals. A host marked
`timedout=true`, missing/duplicate relevant state, unsupported port protocol or
state, future completion, malformed XML, or inconsistent totals is refused.

Limits: UTF-8 (optional BOM), XML 1.0, 2 MiB, 50,000 elements, depth 16, 4,096
represented host records, and one million total host/port observations per
corresponding count family. Input is read at most limit + 1 bytes. Named DTD
references, internal subsets and entity declarations are refused. The bare
`<!DOCTYPE nmaprun>` is accepted. Stylesheet processing instructions are inert;
no DTD, stylesheet, external entity or network resource is fetched.

Only direct host status, direct TCP/UDP/SCTP port states, grouped `extraports`,
and final run totals contribute counts. Duplicate protocol/port pairs within a
host are rejected. Port numbers are used transiently for this check and omitted
from output. Other bounded XML content is ignored, including service and script
contents; it is never executed, rendered, retained, hashed or exported. Reports
from other producer profiles, IP-protocol scans and partial/failed scans are not
supported. Unknown host states are refused rather than labeled down.

## Closed summary and units

| Field | Meaning |
| --- | --- |
| `schema` | `megalodon-nmap-inventory-v1` |
| `started_at`, `finished_at` | Report-declared UTC timestamps, seconds, `Z` suffix |
| `hosts` | Final reported `[up, down]` totals |
| `represented_hosts` | `[up, down]` counts with actual host detail present |
| `explicit_states` | Individually listed ports: open, closed, filtered, unfiltered, open-or-filtered, closed-or-filtered |
| `grouped_states` | `extraports` counts in the same six-state order |
| `protocols` | TCP, UDP, SCTP counts for individually listed ports only |

All arrays contain nonnegative integer counts. Protocol totals equal individually
listed state totals. Grouped counts remain separate because their protocol is not
inferred. Represented hosts cannot exceed reported totals, but reports may omit
host details; a difference remains visible in the HUD. Counts are observations
in this report, not deduplicated assets, incidents, vulnerabilities, live
reachability, bandwidth or complete network coverage. An open port is not itself
a threat. A successful report is a producer claim, not authenticated evidence.

The summary has no addresses, hostnames, port numbers, targets, paths, argv,
banners, script output, raw data or raw-input hash. Browser admission is limited
to 4 KiB, exact keys, duplicate-free JSON, fixed array lengths, coherent sums,
bounded counts and valid nonfuture timestamps. Zero-observation completed
reports are allowed; a failed report is never converted into empty success.

No database write, HTTP import route, watcher, scan launcher, scheduler, egress,
installation or firewall authority is added. This deliberately closes the saved
inventory path only. Live ingestion and independent producer/native-platform
acceptance remain separate work.
