# Completed ClamAV scan summary v1

The optional `megalodon.clamav_summary` command reads one previously completed
`clamscan` text report from standard input and outputs a small JSON file. It does
not start ClamAV, update signatures, read target files or send data to a server.
The shared local and hosted HUD panels load the JSON only when selected by the
operator. The page keeps the selected summary in memory until cleared or closed.

Keep the raw report private: it may contain paths and detection names. Preserve
the scan's exit status alongside it. For an already completed report:

```sh
umask 077
python -m megalodon.clamav_summary --exit-code 0 < completed-clamscan.txt > scan-summary.json
```

Use `--exit-code 1` if the original `clamscan` exited 1. If it exited 2, review
the raw report privately: the exporter refuses error status. The exporter also
refuses a missing or duplicated summary, a missing expected footer field, a
reported nonzero `Total errors`, inconsistent match count/status, trailing
unexpected output, or reports over 1 MiB. Accepted reports use the `clamscan`
summary format with `Known viruses`, numeric engine version, scanned directory
and file counts, infected file count, data scanned/read, time, local start/end
dates. Some optional action fields are refused. `Total errors` is optional when
zero, as the producer prints it only when nonzero. UTF-8 is required.

The `megalodon-clamscan-summary-v1` JSON has exactly nine fields:

| Field | Meaning |
| --- | --- |
| `schema` | Fixed profile identifier |
| `exported_at` | UTC time the exporter ran, not scan time |
| `scan_start_local`, `scan_end_local` | Scanner's wall clock strings; source timezone unknown |
| `engine_version` | Numeric dotted producer version; not signature freshness |
| `scanned_directories`, `scanned_files` | Reported counts |
| `infected_files` | Files with reported matches; not a confirmed compromise count |
| `errors` | Zero; reports with nonzero errors are refused |

No file path, hash, contents, signature, command argument or scan target is
exported. The HUD accepts JSON below 4 KiB, validates the closed schema and
count bounds, and shows three chart cards with explicit local time and saved
status. It never uploads the file or persists it in browser storage.

Counts are only about files the selected report says it scanned. Zero matches
does not prove the target was covered or safe; scanner limits and exclusions
can omit content. False positives need a separate review. Results are not
connected to network traffic severity and are not live scanner telemetry.
Source authenticity and the actual scan command are not independently verified.
