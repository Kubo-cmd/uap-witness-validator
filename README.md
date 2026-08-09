# UAP evidence ledger

This repository is the solver-free transparency companion to `uap-intake-validator`. It records what was declared, what bytes were witnessed, and which claims remain prohibited. It does not contain or replace the validator implementation.

## Why it exists

Scientific software, status decisions, and release artifacts have different lifecycles. The implementation can evolve; a witnessed status must remain historically legible. This repository therefore keeps an independent, append-only Git history for status records and exact document hashes.

The boundary is intentionally narrow:

- no triangulation or conditioning implementation
- no reruns or reinterpretation of the frozen holdout
- no claim that a hash proves scientific correctness
- external comments remain review, not evidence
- every correction is appended rather than silently rewriting the historical statement

## Current status

**UNDETERMINED** — the frozen 6,480-world holdout is an authentic execution of its preregistered protocol, but it is not Council-conformant under the later specification. It is neither a Council PASS nor a retroactive FAIL. No replacement analysis is authorized.

See `STATUS.md` for the human-readable append-only record and `records/` for machine-readable witnessed documents.

## Verify offline

Python 3.9+ and the standard library are sufficient:

```bash
python3 verify_ledger.py
python3 -m unittest discover -s tests -v
```

The verifier checks exact document and record hashes, duplicate JSON keys, contiguous sequence numbers, previous-record bindings, declared status consistency, and the absence of duplicate solver source in the public ledger tree. Any mismatch exits nonzero.

## Repository roles

| Repository | Responsibility |
|---|---|
| `uap-intake-validator` | Canonical software, tests, methodology, and scientific evidence |
| `uap-witness-validator` | This solver-free append-only status and evidence ledger |
| `releases` | Frozen artifact recovery mirror and offline integrity verifier |

Flow:

```text
uap-intake-validator
  ├─ status and evidence hashes witnessed by → uap-witness-validator
  └─ frozen v0.1.0 artifacts mirrored by    → releases
```

Only `uap-intake-validator` should be installed or executed as the research tool.
