#!/usr/bin/env python3
"""Offline verifier for the solver-free UAP evidence ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


class VerificationError(RuntimeError):
    pass


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 1024 * 1024


def _snapshot(value: os.stat_result) -> tuple:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_held(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"cannot open regular file: {path.name}") from exc
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        os.close(descriptor)
        raise VerificationError(f"not a single-link regular file: {path.name}")
    return descriptor


def _confirm_stable(path: Path, descriptor: int, before: os.stat_result) -> None:
    after = os.fstat(descriptor)
    try:
        pathname = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise VerificationError(f"file changed while reading: {path.name}") from exc
    if _snapshot(before) != _snapshot(after):
        raise VerificationError(f"file changed while reading: {path.name}")
    if (pathname.st_dev, pathname.st_ino) != (before.st_dev, before.st_ino):
        raise VerificationError(f"file replaced while reading: {path.name}")


def digest(path: Path) -> tuple[str, int]:
    descriptor = _open_held(path)
    try:
        before = os.fstat(descriptor)
        value = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            value.update(chunk)
        _confirm_stable(path, descriptor, before)
        return value.hexdigest(), before.st_size
    except OSError as exc:
        raise VerificationError(f"cannot hash file: {path.name}") from exc
    finally:
        os.close(descriptor)


def read_held(path: Path, limit: int) -> bytes:
    descriptor = _open_held(path)
    try:
        before = os.fstat(descriptor)
        if before.st_size > limit:
            raise VerificationError(f"file exceeds size limit: {path.name}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise VerificationError(f"file exceeds size limit: {path.name}")
        _confirm_stable(path, descriptor, before)
        return b"".join(chunks)
    except OSError as exc:
        raise VerificationError(f"cannot read file: {path.name}") from exc
    finally:
        os.close(descriptor)


def load_json(path: Path) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise VerificationError(f"non-finite JSON value in {path.name}: {value}")

    try:
        text = read_held(path, MAX_JSON_BYTES).decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse {path.name}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{path.name} must contain a JSON object")
    return value


def require_regular(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise VerificationError("invalid ledger path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts or str(pure) != relative:
        raise VerificationError("invalid ledger path")
    path = root / relative
    try:
        value = path.lstat()
    except OSError as exc:
        raise VerificationError(f"missing ledger member: {relative}") from exc
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise VerificationError(f"ledger member is not a single-link regular file: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError(f"ledger member escapes root: {relative}") from exc
    return path


def verify_member(root: Path, entry: dict) -> tuple[Path, str]:
    if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
        raise VerificationError("invalid ledger member record")
    relative = entry["path"]
    if not isinstance(relative, str):
        raise VerificationError("ledger member path must be a string")
    size = entry["size"]
    expected = entry["sha256"]
    if type(size) is not int or size < 0:
        raise VerificationError(f"invalid ledger member size: {relative}")
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise VerificationError(f"invalid ledger member SHA-256: {relative}")
    path = require_regular(root, relative)
    actual, actual_size = digest(path)
    if actual_size != size:
        raise VerificationError(f"size mismatch: {relative}")
    if actual != expected:
        raise VerificationError(f"SHA-256 mismatch: {relative}")
    return path, actual


def _validate_entries(entries, label: str) -> dict:
    if not isinstance(entries, list) or not entries:
        raise VerificationError(f"ledger must contain {label}")
    paths = []
    folded = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise VerificationError(f"invalid {label} entry")
        path = entry["path"]
        if not isinstance(path, str):
            raise VerificationError(f"invalid {label} path")
        if path in paths or path.casefold() in folded:
            raise VerificationError(f"duplicate {label} path")
        paths.append(path)
        folded.add(path.casefold())
    if paths != sorted(paths):
        raise VerificationError(f"{label} must be sorted by path")
    return {entry["path"]: entry for entry in entries}


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

    forbidden = ledger["forbidden_working_source_paths"]
    if (
        not isinstance(forbidden, list)
        or not forbidden
        or any(not isinstance(item, str) for item in forbidden)
        or len(forbidden) != len(set(forbidden))
    ):
        raise VerificationError("invalid forbidden-source declaration")
    for relative in forbidden:
        if (root / relative).exists() or (root / relative).is_symlink():
            raise VerificationError(f"duplicate solver source present: {relative}")

    document_entries = ledger["documents"]
    record_entries = ledger["records"]
    document_map = _validate_entries(document_entries, "documents")
    _validate_entries(record_entries, "records")

    document_hashes = {}
    for entry in document_entries:
        _, actual = verify_member(root, entry)
        document_hashes[entry["path"]] = actual

    status_path = require_regular(root, "STATUS.md")
    try:
        status_text = read_held(status_path, MAX_STATUS_BYTES).decode("utf-8")
    except UnicodeError as exc:
        raise VerificationError("STATUS.md is not valid UTF-8") from exc
    if "Append-only." not in status_text or "UNDETERMINED" not in status_text:
        raise VerificationError("human status record lacks controlling markers")

    council_path = "records/holdout-2026080502.council-status.json"
    if council_path not in document_map:
        raise VerificationError("canonical status document is not manifest-bound")
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
        if type(record.get("sequence")) is not int or record["sequence"] != expected_sequence:
            raise VerificationError("witness record sequence is not contiguous")
        prior = record.get("previous_record_sha256")
        if prior is not None and (not isinstance(prior, str) or not HEX64.fullmatch(prior)):
            raise VerificationError("witness record previous hash is invalid")
        if prior != previous:
            raise VerificationError("witness record previous hash mismatch")
        if record.get("canonical_project") != ledger["canonical_project"]:
            raise VerificationError("witness record canonical project mismatch")
        if record.get("canonical_tag") != "v0.1.0":
            raise VerificationError("witness record tag mismatch")
        if not isinstance(record.get("canonical_source_commit"), str) or not HEX40.fullmatch(record["canonical_source_commit"]):
            raise VerificationError("witness record source commit is invalid")
        if record.get("council_inferential_status") != "UNDETERMINED":
            raise VerificationError("witness record changed inferential status")
        if not isinstance(record.get("release_archive_sha256"), str) or not HEX64.fullmatch(record["release_archive_sha256"]):
            raise VerificationError("witness record archive digest is invalid")
        if not isinstance(record.get("scope"), str) or not record["scope"] or len(record["scope"].encode("utf-8")) > 4096:
            raise VerificationError("witness record scope is invalid")
        non_claims = record.get("non_claims")
        if not isinstance(non_claims, list) or not non_claims or any(not isinstance(item, str) or not item for item in non_claims):
            raise VerificationError("witness record non-claims are invalid")
        bound_documents = record.get("documents")
        if not isinstance(bound_documents, list):
            raise VerificationError("witness record documents are invalid")
        bound = {}
        for item in bound_documents:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise VerificationError("invalid witness document binding")
            path_name = item["path"]
            sha = item["sha256"]
            if not isinstance(path_name, str) or path_name in bound:
                raise VerificationError("duplicate witness document binding")
            if not isinstance(sha, str) or not HEX64.fullmatch(sha):
                raise VerificationError("invalid witness document digest")
            bound[path_name] = sha
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


def verify_transition(previous_root: Path, current_root: Path) -> dict:
    previous_root = previous_root.resolve()
    current_root = current_root.resolve()
    previous_result = verify(previous_root)
    current_result = verify(current_root)
    old = load_json(require_regular(previous_root, "LEDGER.json"))
    new = load_json(require_regular(current_root, "LEDGER.json"))

    old_status = read_held(require_regular(previous_root, "STATUS.md"), MAX_STATUS_BYTES)
    new_status = read_held(require_regular(current_root, "STATUS.md"), MAX_STATUS_BYTES)
    if not new_status.startswith(old_status):
        raise VerificationError("STATUS.md is not an exact append-only extension")

    old_records = old["records"]
    new_records = new["records"]
    if len(new_records) < len(old_records) or new_records[:len(old_records)] != old_records:
        raise VerificationError("record list is not an exact append-only prefix")
    for entry in old_records:
        relative = entry["path"]
        old_digest, old_size = digest(require_regular(previous_root, relative))
        new_digest, new_size = digest(require_regular(current_root, relative))
        if (old_digest, old_size) != (new_digest, new_size):
            raise VerificationError(f"historical record changed: {relative}")

    old_documents = {entry["path"]: entry for entry in old["documents"] if entry["path"] != "STATUS.md"}
    new_documents = {entry["path"]: entry for entry in new["documents"] if entry["path"] != "STATUS.md"}
    for relative, entry in old_documents.items():
        if new_documents.get(relative) != entry:
            raise VerificationError(f"historical document binding changed: {relative}")
        old_digest, old_size = digest(require_regular(previous_root, relative))
        new_digest, new_size = digest(require_regular(current_root, relative))
        if (old_digest, old_size) != (new_digest, new_size):
            raise VerificationError(f"historical document changed: {relative}")

    return {
        "ok": True,
        "append_only_transition": True,
        "previous_records": previous_result["records"],
        "current_records": current_result["records"],
        "status_prefix_preserved": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--previous-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.previous_root is None:
            result = verify(args.root)
        else:
            result = verify_transition(args.previous_root, args.root)
    except VerificationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
