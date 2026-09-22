# Imported security scan receipt

Status: 📜 contract only — no scanner was invoked and no fresh vulnerability
clearance is claimed by this change.

`megalodon.security-scan-receipt/v1` is a closed import boundary for output from
CodeQL, Codex Security, or another automated scanner. A receipt binds:

- the exact repository commit and tree;
- scanner name, version, and configuration digest;
- scan timing and finite completeness state;
- stable finding IDs, rules, severity, and location fingerprints;
- expiring suppressions with reasons;
- a digest-bound raw-result artifact; and
- the authentication class of the imported observation.

```bash
python tools/security_scan_receipt.py receipt.json \
  --expected-commit <40-char-commit> \
  --expected-tree <40-char-tree>
```

The validator checks summary parity, unique finding IDs, suppression completeness
and expiry relative to the scan, source identity, and scan chronology. A failed
scan cannot assert findings; a partial scan remains partial.

All authority fields are fixed to `false`. A valid receipt is not merge
authorization, independent security acceptance, release approval, deployment
approval, host authority, provider containment evidence, or proof that no
vulnerability exists. The raw scanner artifact remains the review source.
