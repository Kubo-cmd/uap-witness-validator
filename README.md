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
python3 -I -S -B verify_ledger.py
python3 -B -m unittest discover -s tests -v
```

To verify a proposed ledger against a previously trusted checkout:

```bash
python3 -I -S -B verify_ledger.py /path/to/current --previous-root /path/to/previous
```

The normal verifier checks held-file hashes, bounded and duplicate-key-safe JSON,
contiguous sequence numbers, previous-record bindings, status consistency, and
absence of the manifest-enumerated known duplicate solver paths. This is a
path-denylist check, not semantic detection of arbitrarily renamed solver code.
Transition mode additionally requires every historical record to remain
byte-exact and `STATUS.md` to be an exact prefix extension. Any mismatch exits
nonzero.

A standalone mutable manifest proves internal consistency, not authenticity
against coordinated history rewriting. Strong continuity still requires a
trusted prior checkout, pinned commit, or external checkpoint.

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
