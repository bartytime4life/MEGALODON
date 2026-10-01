# Managed evidence: measured capacity

These benchmarks measure local sensor-summary ingestion and bounded history queries. They do not measure packet capture, network throughput, simultaneous operating-system sockets, or the resource cost of the full desktop HUD and support apps.

## Reproduce

Run from the repository with its Python environment. No network traffic, capture sockets, geolocation requests, or installed services are used. Each case runs in a fresh process and creates an owner-private temporary input file and evidence store, then removes both. The JSON reports contain no captured user traffic.

```bash
.venv312/bin/python tools/benchmark_flow_ingestion.py --connections 10000 100000 --source suricata --mode burst --output docs/benchmarks/expanded-hud-suricata-burst.json
.venv312/bin/python tools/benchmark_flow_ingestion.py --connections 10000 100000 --source zeek --mode burst --output docs/benchmarks/expanded-hud-zeek-burst.json
.venv312/bin/python tools/benchmark_flow_ingestion.py --connections 100000 --source suricata --mode sustained --arrival-rate 3000 --output docs/benchmarks/expanded-hud-suricata-sustained.json
```

Run the commands sequentially so they do not compete with each other. File ownership checks remain enabled. If the development sandbox remaps temporary-file ownership, use the host's approved execution path; do not relax those checks.

## What the workload includes

- Unique synthetic connection identities with overlapping observation intervals. Suricata records are periodic cumulative summaries; Zeek records are completed connection summaries. This is not a set of real active sockets.
- One priming record establishes the input checkpoint before measurement. Fresh attachment to an existing large log deliberately starts at a bounded tail; that admission gap is covered by regression tests instead.
- **Burst:** the remaining summaries already exist in the input file. Direct polling drains them without the worker's scheduling waits, measuring backlog-drain throughput.
- **Sustained:** a concurrent producer appends roughly 20 ms batches at the requested rate. The actual `FlowIngestor` worker runs, including its 100 ms backlog and 1 s idle waits. Timing includes source generation, scheduling waits, and the final drain.
- One concurrent reader repeatedly requests 50 history records, waiting 20 ms after each completed query. The reported interval is not a fixed request-per-second guarantee.
- Server storage profile, seven-day retention, 1 GiB cap, 16 MiB segment target, SQLite WAL, and the normal synchronous setting. The tiny test dataset does not exercise cap eviction or days-long retention.
- Real normalizers, transactional checkpoints, managed evidence writes, and live projection callbacks. Geographic lookups are disabled for synthetic addresses.
- Verification checks every persisted source identity in exact insertion order across segments, source provenance, callback count, rejected records, input gaps, final backlog, storage evictions, and query errors.

## Interpretation and limits

Burst throughput and sustained arrival throughput answer different questions. A short paced test that eventually drains successfully does not establish stable 24/7 capacity. Compare the configured arrival rate, actual producer rate, backlog peak, and drain time before choosing a collection workload.

Backlog peaks are sampled every 20 ms in sustained mode and before each direct burst poll. A short peak between samples can be missed. Reported query latency includes SQLite contention with the writer. Twenty-five additional queries measure the quiet store after ingestion.

RSS is reported both from `/proc/self/status` sampling and the process high-water counter; Linux accounting can differ between the two. The result includes the Python collector, generator, query reader, and verification work. Source input files are outside managed storage, and their size is reported separately. Disk reports include logical and allocated bytes, including catalog and WAL files present at measurement.

The live projection retains at most 512 connections and returns at most 128. Projection evictions are explicit visual coverage limits; all admitted summaries can still be retained in managed evidence. These tests exercise connection summaries, not the finite 2,000-frame Zeek sample path, packet recording, payload retention, model inference, or browser rendering.

## Results

The saved reports below contain the measurements and SHA-256 hashes for the benchmark script and each measured implementation file. Per-case hashes identify the code used by that case; compare them with the current checkout before treating a result as current.

- [Suricata burst](benchmarks/expanded-hud-suricata-burst.json)
- [Zeek burst](benchmarks/expanded-hud-zeek-burst.json)
- [Suricata sustained](benchmarks/expanded-hud-suricata-sustained.json)

Measured on 2026-10-01 UTC: AMD Ryzen 9 9950X, 32 logical CPUs, 123.46 GiB visible RAM, Linux `7.0.0-34-generic`, Python 3.12.3, and an ext4 temporary-file filesystem. Other workstation activity was present. This is a workstation measurement, not a minimum hardware specification.

| Source / mode | Summaries | Admitted summaries/s | Concurrent history p95 | Peak RSS estimate | Managed disk |
|---|---:|---:|---:|---:|---:|
| Suricata burst | 10,000 | 5,160 | 28.63 ms | 28.07 MiB | 4.79 MiB |
| Suricata burst | 100,000 | 4,962 | 29.15 ms | 28.77 MiB | 50.40 MiB |
| Zeek burst | 10,000 | 5,140 | 32.60 ms | 28.26 MiB | 4.79 MiB |
| Zeek burst | 100,000 | 4,997 | 29.87 ms | 30.29 MiB | 47.51 MiB |
| Suricata sustained | 100,000 | 2,824 | 51.96 ms | 28.30 MiB | 50.40 MiB |

The RSS column uses the larger of the two reported RSS estimates. Disk is logical managed size; allocated size and external synthetic input size remain separate in the reports.

The sustained producer delivered **2,999.96 summaries/s for 33.33 seconds**. Admission finished at **35.41 seconds**, after a **2.07-second drain**. Sampled backlog peaked at **5,903 records / 2.04 MiB** near the end of arrivals. The queue grew during this test: the result establishes lossless admission of this finite workload, not indefinitely stable operation at 3,000/s.

Every case persisted every expected source identity in order and finished with **zero final backlog, rejected records, input admission gaps, query errors, or storage evictions**. The 100,000-record cases evicted 99,488 identities from the bounded live projection, while retaining all 100,000 evidence records. The returned visual slice remained at most 128 connections.

All five cases used the following implementation hashes. These measurements precede the Balanced recording changes; see [the subsequent write-efficiency comparison](efficient-recording-reports.md) for that implementation. They are not a current-build capacity guarantee:

| File | SHA-256 prefix (full hash in reports) |
|---|---|
| `megalodon/evidence_storage.py` | `f9f5771b5db0` |
| `megalodon/flow_ingestion.py` | `8f101c0eb22e` |
| `megalodon/live_connections.py` | `48997cade287` |
| `tools/benchmark_flow_ingestion.py` | `c2ff43b19a07` |
