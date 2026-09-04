# Security Policy

## Supported versions

Security fixes are prepared against the current `main` branch. Historical ledger records remain append-only and are not rewritten.

## Report a vulnerability

Send vulnerability reports privately to `Kubo100x@proton.me`.

Include:

- the affected file, commit, or release;
- the impact and expected security boundary;
- minimal reproduction steps or a proof of concept;
- any suggested mitigation;
- whether the issue is already public.

Do not include vulnerability details in a public issue or pull request. You should receive an acknowledgement within seven days. Coordinated disclosure timing will be agreed after the report is reproduced and assessed.

## Scope

Security reports are appropriate for issues such as:

- verifier behavior that accepts an invalid ledger;
- bypasses of held-file, sequence, duplicate-key, or transition checks;
- unsafe path handling;
- dependency or workflow compromise;
- accidental disclosure of sensitive data.

Scientific disagreement, status interpretation, and requests to rerun or reinterpret the frozen holdout are not security vulnerabilities. Use a normal issue for non-sensitive questions.

## Integrity boundary

A successful hash check proves byte identity against the supplied manifest. It does not by itself prove scientific correctness or protect against coordinated rewriting of both a file and its mutable manifest. Strong continuity requires a trusted prior checkout, pinned commit, or external checkpoint.
