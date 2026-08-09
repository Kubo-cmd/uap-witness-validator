#!/usr/bin/env python3
"""Offline verifier for the solver-free UAP evidence ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


class VerificationError(RuntimeError):
    pass


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_json(path: Path) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse {path.name}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{path.name} must contain a JSON object")
    return value


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_regular(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise VerificationError("invalid ledger path")
    path = root / relative
    try:
        path.lstat()
    except OSError as exc:
        raise VerificationError(f"missing ledger member: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"ledger member is not a regular file: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError(f"ledger member escapes root: {relative}") from exc
    return path


def verify_member(root: Path, entry: dict) -> tuple[Path, str]:
    if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
        raise VerificationError("invalid ledger member record")
    path = require_regular(root, entry["path"])
    if not isinstance(entry["size"], int) or path.stat().st_size != entry["size"]:
        raise VerificationError(f"size mismatch: {entry['path']}")
    actual = digest(path)
    if actual != entry["sha256"]:
        raise VerificationError(f"SHA-256 mismatch: {entry['path']}")
    return path, actual


def verify(root: Path) -> dict:
    root = root.resolve()
    ledger = load_json(require_regular(root, "LEDGER.json"))
    expected_keys = {
        "schema", "mode", "canonical_project", "documents", "records",
        "forbidden_working_source_paths",
    }
    if set(ledger) != expected_keys or ledger.get("schema") != "uap-witness-ledger/v1":
        raise VerificationError("unsupported ledger schema")
    if ledger.get("mode") != "append-only":
        raise VerificationError("ledger must declare append-only mode")
    if ledger.get("canonical_project") != "uap-intake-validator":
        raise VerificationError("unexpected canonical project")

    forbidden = ledger.get("forbidden_working_source_paths")
    if not isinstance(forbidden, list) or any(not isinstance(item, str) for item in forbidden):
        raise VerificationError("invalid forbidden-source declaration")
    for relative in forbidden:
        if (root / relative).exists() or (root / relative).is_symlink():
            raise VerificationError(f"duplicate solver source present: {relative}")

    document_entries = ledger.get("documents")
    record_entries = ledger.get("records")
    if not isinstance(document_entries, list) or not isinstance(record_entries, list):
        raise VerificationError("documents and records must be arrays")
    if not document_entries or not record_entries:
        raise VerificationError("ledger must contain documents and records")

    document_hashes = {}
    for entry in document_entries:
        path, actual = verify_member(root, entry)
        relative = entry["path"]
        if relative in document_hashes:
            raise VerificationError(f"duplicate document entry: {relative}")
        document_hashes[relative] = actual

    status_text = (root / "STATUS.md").read_text(encoding="utf-8")
    if "Append-only." not in status_text or "UNDETERMINED" not in status_text:
        raise VerificationError("human status record lacks controlling markers")

    council_path = "records/holdout-2026080502.council-status.json"
    council = load_json(require_regular(root, council_path))
    if council.get("schema") != "uap_crossing_angle_holdout_council_status/v1":
        raise VerificationError("canonical status document schema mismatch")
    if council.get("council_inferential_status") != "UNDETERMINED":
        raise VerificationError("canonical status document changed inferential status")
    if council.get("append_only") is not True:
        raise VerificationError("canonical status document is not append-only")

    previous = None
    record_hashes = []
    for expected_sequence, entry in enumerate(record_entries, start=1):
        path, actual = verify_member(root, entry)
        record = load_json(path)
        required_record_keys = {
            "schema", "sequence", "previous_record_sha256", "record_type",
            "canonical_project", "canonical_tag", "canonical_source_commit",
            "release_archive_sha256", "council_inferential_status", "documents",
            "scope", "non_claims",
        }
        if set(record) != required_record_keys or record.get("schema") != "uap-witness-record/v1":
            raise VerificationError("witness record schema mismatch")
        if record.get("sequence") != expected_sequence:
            raise VerificationError("witness record sequence is not contiguous")
        if record.get("previous_record_sha256") != previous:
            raise VerificationError("witness record previous hash mismatch")
        if record.get("canonical_project") != ledger["canonical_project"]:
            raise VerificationError("witness record canonical project mismatch")
        if record.get("council_inferential_status") != "UNDETERMINED":
            raise VerificationError("witness record changed inferential status")
        if not HEX64.fullmatch(str(record.get("release_archive_sha256", ""))):
            raise VerificationError("witness record archive digest is invalid")
        bound_documents = record.get("documents")
        if not isinstance(bound_documents, list):
            raise VerificationError("witness record documents are invalid")
        bound = {}
        for item in bound_documents:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise VerificationError("invalid witness document binding")
            if item["path"] in bound:
                raise VerificationError("duplicate witness document binding")
            bound[item["path"]] = item["sha256"]
        if bound != document_hashes:
            raise VerificationError("witness record document bindings mismatch")
        previous = actual
        record_hashes.append(actual)

    return {
        "ok": True,
        "status": "UNDETERMINED",
        "documents": len(document_hashes),
        "records": len(record_hashes),
        "solver_source_present": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root)
    except VerificationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
