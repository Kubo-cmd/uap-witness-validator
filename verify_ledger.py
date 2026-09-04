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
import unicodedata


class VerificationError(RuntimeError):
    pass


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 1024 * 1024
CANONICAL_COUNCIL_STATUS_SEMANTIC_SHA256 = (
    "7184171e70458d5cea6badd0e75a0d2e9a09fdfcb811e9b6677c07355d1560b5"
)

CANONICAL_CONTROLLING_STATEMENT = (
    "This holdout result is valid only under its own frozen preregistration. Under that protocol, "
    "criteria 1–3 passed and criterion 5 failed; the recorded result supports the protocol’s "
    "physical-error-law claim but not its production-output claim. Because the frozen design has "
    "known Council-method and evidence-control deviations, this result is NOT Council-conformant. "
    "No rerun or post-hoc replacement analysis is permitted."
)
CANONICAL_COUNCIL_STATUS_STATEMENT = (
    "The 6480-world holdout is an authentic execution of frozen protocol v1, but it is non-certifying "
    "under the later Council specification. Its Council-level inferential status is UNDETERMINED—not "
    "PASS and not retroactive FAIL. No recomputation, reinterpretation, or replacement analysis is "
    "authorized."
)
CANONICAL_PROHIBITED_ACTIONS = (
    "rerun or continue the completed holdout",
    "use a replacement seed or add holdout worlds",
    "apply post-hoc Satterthwaite inference or a replacement bootstrap to the frozen rows",
    "apply a retrospective decision rule",
    "edit, replace, or reseal the frozen protocol, result, rows, or original manifest",
    "describe the result as Council-conformant, Council-PASS, or retroactively Council-FAIL",
    "claim a retroactive sentinel or dependency seal proves execution-time properties",
)
CONTRADICTORY_STATUS_PATTERNS = (
    re.compile(
        r"\bcouncil"
        r"(?:[-\s]+(?:status|result|outcome|verdict|decision))?"
        r"\s*(?:is|was|remains|=|:)?\s*(?:\w+\s+){0,2}"
        r"(?:a\s+)?(?:council[-\s]*)?pass(?:ed)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bcouncil[-\s]+(?:pass|conformant)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bproduction[-_\s]+outputs?(?:[-_\s]+claim)?\s+"
        r"(?:is|are|was|were|remains|remain|=|:)\s*(?:\w+\s+){0,2}"
        r"(?:supported|valid|confirmed|proven|passes)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:supports?|validates?|confirms?|proves?)\s+(?:the\s+)?"
        r"production[-_\s]+outputs?(?:[-_\s]+claim)?\b",
        re.IGNORECASE,
    ),
)
CLAIM_SAFEGUARD = re.compile(
    r"\b(?:not|never|neither|without|if|unless|hypothetically|"
    r"deny|denies|denied|forbid|forbids|forbidden|prohibit|prohibits|prohibited)\b"
    r"[^,;:.!?—–]{0,48}$",
    re.IGNORECASE,
)
CLAIM_SAFEGUARD_SUFFIX = re.compile(
    r"^[^,;:.!?—–]{0,48}\b(?:hypothetical|hypothetically|counterfactual|"
    r"counterfactually|forbidden|prohibited|denied|not\s+allowed)\b",
    re.IGNORECASE,
)
CLAIM_WARNING_PREFIX = re.compile(
    r"(?:\b(?:quoted|hypothetical)\s+warning|"
    r"\b(?:the\s+)?(?:following\s+)?statement\s+is\s+(?:forbidden|prohibited))"
    r"\s*:\s*[\"'“‘]?\s*$",
    re.IGNORECASE,
)


def contains_contradictory_status_claim(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(character for character in normalized if unicodedata.category(character) != "Cf")
    normalized = normalized.replace("_", " ")
    normalized = normalized.translate(str.maketrans("", "", "*`~[](){}"))
    normalized = re.sub(r"\s+", " ", normalized)
    for sentence in re.split(r"[.!?]+(?:\s+|$)", normalized):
        for pattern in CONTRADICTORY_STATUS_PATTERNS:
            for match in pattern.finditer(sentence):
                prefix = sentence[max(0, match.start() - 64):match.start()]
                suffix = sentence[match.end():match.end() + 64]
                if (
                    not CLAIM_SAFEGUARD.search(prefix)
                    and not CLAIM_WARNING_PREFIX.search(prefix)
                    and not CLAIM_SAFEGUARD_SUFFIX.search(suffix)
                    and not re.search(
                        r"\b(?:not|never|neither|without)\b", match.group(0), re.IGNORECASE
                    )
                ):
                    return True
    return False


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


def load_json_bytes(data: bytes, name: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key in {name}: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise VerificationError(f"non-finite JSON value in {name}: {value}")

    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse {name}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{name} must contain a JSON object")
    return value


def load_json(path: Path) -> dict:
    return load_json_bytes(read_held(path, MAX_JSON_BYTES), path.name)


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


def validate_council_status(value: dict) -> None:
    required = {
        "schema", "experiment_id", "recorded_utc", "decision",
        "council_inferential_status", "append_only", "frozen_protocol_interpretation",
        "controlling_statement", "council_status_statement", "deviations",
        "frozen_artifacts_sha256", "currently_observed_unsealed_dependency",
        "prohibited_actions", "council_workstreams",
    }
    if set(value) != required:
        raise VerificationError("canonical status document keys are invalid")
    if value["schema"] != "uap_crossing_angle_holdout_council_status/v1":
        raise VerificationError("canonical status document schema mismatch")
    if value["decision"] != "NOT_COUNCIL_CONFORMANT":
        raise VerificationError("canonical status decision mismatch")
    if value["council_inferential_status"] != "UNDETERMINED":
        raise VerificationError("canonical status must remain UNDETERMINED")
    if value["append_only"] is not True:
        raise VerificationError("canonical status must remain append-only")
    for key in ("experiment_id", "recorded_utc", "controlling_statement", "council_status_statement"):
        if not isinstance(value[key], str) or not value[key]:
            raise VerificationError(f"canonical status string is invalid: {key}")
    if value["controlling_statement"] != CANONICAL_CONTROLLING_STATEMENT:
        raise VerificationError("canonical controlling statement mismatch")
    if value["council_status_statement"] != CANONICAL_COUNCIL_STATUS_STATEMENT:
        raise VerificationError("canonical council status statement mismatch")

    protocol = value["frozen_protocol_interpretation"]
    protocol_keys = {
        "authentic_execution_of_protocol_v1", "criteria_1_to_3_passed", "criterion_5_passed",
        "physical_error_law_supported_under_protocol_v1", "production_output_supported",
    }
    if not isinstance(protocol, dict) or set(protocol) != protocol_keys:
        raise VerificationError("canonical frozen interpretation keys are invalid")
    expected_protocol = {
        "authentic_execution_of_protocol_v1": True,
        "criteria_1_to_3_passed": True,
        "criterion_5_passed": False,
        "physical_error_law_supported_under_protocol_v1": True,
        "production_output_supported": False,
    }
    if protocol != expected_protocol:
        raise VerificationError("canonical frozen interpretation is contradictory")

    deviations = value["deviations"]
    if not isinstance(deviations, list) or not deviations:
        raise VerificationError("canonical status deviations are invalid")
    deviation_ids = set()
    base_keys = {"id", "frozen_v1_choice", "later_council_requirement"}
    for deviation in deviations:
        if not isinstance(deviation, dict) or set(deviation) not in {frozenset(base_keys), frozenset(base_keys | {"limit"})}:
            raise VerificationError("canonical status deviation keys are invalid")
        if any(not isinstance(deviation[key], str) or not deviation[key] for key in deviation):
            raise VerificationError("canonical status deviation value is invalid")
        if deviation["id"] in deviation_ids:
            raise VerificationError("canonical status deviation IDs are not unique")
        deviation_ids.add(deviation["id"])

    frozen_hashes = value["frozen_artifacts_sha256"]
    expected_frozen_paths = {
        "evidence/preregistration.json",
        "evidence/results/holdout-2026080502.json",
        "evidence/results/holdout-2026080502.rows.json",
        "evidence/results/holdout-2026080502.rows.csv",
        "evidence/results/holdout-2026080502.manifest.json",
    }
    if not isinstance(frozen_hashes, dict) or set(frozen_hashes) != expected_frozen_paths:
        raise VerificationError("canonical frozen artifact set is invalid")
    if any(not isinstance(item, str) or not HEX64.fullmatch(item) for item in frozen_hashes.values()):
        raise VerificationError("canonical frozen artifact digest is invalid")

    dependency = value["currently_observed_unsealed_dependency"]
    if not isinstance(dependency, dict) or set(dependency) != {"path", "sha256", "observed_utc", "disclaimer"}:
        raise VerificationError("canonical observed dependency keys are invalid")
    if dependency["path"] != "uap_conditioning.py" or not isinstance(dependency["sha256"], str) or not HEX64.fullmatch(dependency["sha256"]):
        raise VerificationError("canonical observed dependency binding is invalid")
    if not isinstance(dependency["observed_utc"], str) or not isinstance(dependency["disclaimer"], str):
        raise VerificationError("canonical observed dependency metadata is invalid")

    prohibited = value["prohibited_actions"]
    if not isinstance(prohibited, list) or not prohibited:
        raise VerificationError("canonical prohibited actions are invalid")
    if any(not isinstance(item, str) or not item.strip() for item in prohibited):
        raise VerificationError("canonical prohibited action is invalid")
    if len(prohibited) != len(set(prohibited)):
        raise VerificationError("canonical prohibited actions are not unique")
    if tuple(prohibited) != CANONICAL_PROHIBITED_ACTIONS:
        raise VerificationError("canonical prohibited actions mismatch")

    workstreams = value["council_workstreams"]
    if not isinstance(workstreams, list) or not workstreams:
        raise VerificationError("canonical council workstreams are invalid")
    seats = set()
    for workstream in workstreams:
        if not isinstance(workstream, dict) or set(workstream) != {"seat", "vote"}:
            raise VerificationError("canonical council workstream keys are invalid")
        if not isinstance(workstream["seat"], str) or not workstream["seat"].strip():
            raise VerificationError("canonical council seat is invalid")
        if not isinstance(workstream["vote"], str) or not workstream["vote"].strip():
            raise VerificationError("canonical council vote is invalid")
        if workstream["seat"] in seats:
            raise VerificationError("canonical council seats are not unique")
        seats.add(workstream["seat"])

    semantic_bytes = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if hashlib.sha256(semantic_bytes).hexdigest() != CANONICAL_COUNCIL_STATUS_SEMANTIC_SHA256:
        raise VerificationError("canonical status document semantic digest mismatch")


def verify_member(root: Path, entry: dict) -> tuple[Path, str, bytes]:
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
    data = read_held(path, max(MAX_JSON_BYTES, MAX_STATUS_BYTES))
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != size:
        raise VerificationError(f"size mismatch: {relative}")
    if actual != expected:
        raise VerificationError(f"SHA-256 mismatch: {relative}")
    return path, actual, data


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
            raise VerificationError(f"known duplicate solver path present: {relative}")

    document_entries = ledger["documents"]
    record_entries = ledger["records"]
    document_map = _validate_entries(document_entries, "documents")
    _validate_entries(record_entries, "records")

    document_hashes = {}
    document_bytes = {}
    for entry in document_entries:
        _, actual, data = verify_member(root, entry)
        document_hashes[entry["path"]] = actual
        document_bytes[entry["path"]] = data

    try:
        status_text = document_bytes["STATUS.md"].decode("utf-8")
    except KeyError as exc:
        raise VerificationError("STATUS.md is not manifest-bound") from exc
    except UnicodeError as exc:
        raise VerificationError("STATUS.md is not valid UTF-8") from exc
    if "Append-only." not in status_text or "UNDETERMINED" not in status_text:
        raise VerificationError("human status record lacks controlling markers")

    council_path = "records/holdout-2026080502.council-status.json"
    if council_path not in document_map:
        raise VerificationError("canonical status document is not manifest-bound")
    council = load_json_bytes(document_bytes[council_path], Path(council_path).name)
    validate_council_status(council)

    previous = None
    record_hashes = []
    for expected_sequence, entry in enumerate(record_entries, start=1):
        path, actual, data = verify_member(root, entry)
        record = load_json_bytes(data, path.name)
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
        if not bound:
            raise VerificationError("witness record must bind at least one document")
        if expected_sequence == len(record_entries) and bound != document_hashes:
            raise VerificationError("latest witness record document bindings mismatch")
        previous = actual
        record_hashes.append(actual)

    return {
        "ok": True,
        "status": "UNDETERMINED",
        "documents": len(document_hashes),
        "records": len(record_hashes),
        "known_solver_paths_present": False,
    }


def verify_transition(previous_root: Path, current_root: Path) -> dict:
    previous_root = previous_root.resolve()
    current_root = current_root.resolve()
    previous_result = verify(previous_root)
    current_result = verify(current_root)
    old = load_json(require_regular(previous_root, "LEDGER.json"))
    new = load_json(require_regular(current_root, "LEDGER.json"))

    old_forbidden = set(old["forbidden_working_source_paths"])
    new_forbidden = set(new["forbidden_working_source_paths"])
    if not old_forbidden.issubset(new_forbidden):
        raise VerificationError("forbidden-source policy is not monotonic")

    old_status = read_held(require_regular(previous_root, "STATUS.md"), MAX_STATUS_BYTES)
    new_status = read_held(require_regular(current_root, "STATUS.md"), MAX_STATUS_BYTES)
    if not new_status.startswith(old_status):
        raise VerificationError("STATUS.md is not an exact append-only extension")
    appended_status = new_status[len(old_status):].decode("utf-8")
    if contains_contradictory_status_claim(appended_status):
        raise VerificationError("contradictory status claim appended to STATUS.md")

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
