# Contributing

Thank you for helping improve the witness ledger. Changes should preserve its narrow role as a solver-free, append-only record of status and evidence hashes.

## Before you start

- Open an issue for behavior changes or material policy changes.
- Do not add triangulation, conditioning, solver, or holdout-reinterpretation code.
- Do not rewrite historical records or shorten `STATUS.md`.
- Keep corrections append-only and bind them to the preceding record.
- Report security-sensitive findings through the private route in `SECURITY.md`, not in a public issue.

## Local setup

Python 3.9 or newer is required. The verifier uses only the standard library. The test suite is run with `pytest` in CI.

```bash
git clone https://github.com/Kubo-cmd/uap-witness-validator.git
cd uap-witness-validator
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip pytest pytest-asyncio
```

## Verify a change

Run the standalone verifier in isolated mode, then the complete test suite:

```bash
python3 -I -S -B verify_ledger.py
python -m pytest tests/ -q
```

For a proposed ledger transition, also compare it with a previously trusted checkout:

```bash
python3 -I -S -B verify_ledger.py /path/to/current --previous-root /path/to/previous
```

The transition check must preserve every historical record byte-for-byte and extend `STATUS.md` by exact prefix.

## Pull requests

Create a focused branch and keep each pull request limited to one concern. A pull request should:

- explain the problem and the bounded change;
- list the exact verification commands and results;
- identify any security, compatibility, or append-only risks;
- include tests for verifier behavior changes;
- avoid unrelated formatting or cleanup;
- pass every required CI check.

Do not commit generated caches, virtual environments, credentials, private reports, or unrelated release artifacts.

## Commit messages

Use a short imperative subject that describes the change, for example:

```text
docs: add repository contribution guidance
```

## Review boundary

A passing test or hash check is evidence for the behavior it exercises, not proof of scientific correctness. Reviewers may request a trusted prior checkout, pinned commit, or external checkpoint when continuity claims depend on history outside the proposed branch.
