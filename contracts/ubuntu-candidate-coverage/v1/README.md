# Ubuntu candidate coverage contract v1

`megalodon.ubuntu-candidate-coverage/v1` maps the existing Ubuntu candidate
manifest to retained receipts. It supplements rather than replaces:

- `tools/ubuntu_release_evidence.py` for the nine-check/two-artifact manifest;
- `tools/release_evidence_packet.py` for SBOM/provenance packet binding; and
- `tools/installed_recovery_evidence.py` for bounded synthetic recovery phases.

The semantic validator enforces exact commit/tree and candidate-manifest digest
binding, ordered check/artifact/optional/gate sets, status parity with the
source manifest, all-or-nothing evidence pointers, independent authentication
for independent disposition, and a synthetic-evidence completion refusal.

`complete` is evidence coverage only. It is not release authority and it does
not change the candidate packet's `generated_unreviewed` status.
