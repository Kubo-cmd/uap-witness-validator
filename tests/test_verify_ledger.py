import hashlib
import json
import os
from pathlib import Path
from unittest import mock
import shutil
import tempfile
import unittest

import verify_ledger


ROOT = Path(__file__).resolve().parents[1]
RECORD = "records/0001-release-status-witness.json"


class LedgerVerificationTests(unittest.TestCase):
    def copy_ledger(self, destination: Path) -> None:
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part == ".git" for part in relative.parts):
                continue
            target = destination / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

    def update_manifest_hash(self, root: Path, relative: str) -> None:
        manifest_path = root / "LEDGER.json"
        manifest = json.loads(manifest_path.read_text())
        path = root / relative
        for section in ("documents", "records"):
            for entry in manifest[section]:
                if entry["path"] == relative:
                    entry["size"] = path.stat().st_size
                    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))

    def update_record_document_hash(self, root: Path, relative: str) -> None:
        path = root / RECORD
        record = json.loads(path.read_text())
        document = root / relative
        for entry in record["documents"]:
            if entry["path"] == relative:
                entry["sha256"] = hashlib.sha256(document.read_bytes()).hexdigest()
        path.write_text(json.dumps(record))
        self.update_manifest_hash(root, RECORD)

    def append_status_witness(self, root: Path, statement: str) -> None:
        status = root / "STATUS.md"
        status.write_text(status.read_text() + f"\n## Review note\n\n{statement}\n")
        self.update_manifest_hash(root, "STATUS.md")

        first_path = root / RECORD
        second = json.loads(first_path.read_text())
        second["sequence"] = 2
        second["previous_record_sha256"] = hashlib.sha256(first_path.read_bytes()).hexdigest()
        second["record_type"] = "status_append_witness"
        second["scope"] = "Witnesses an append-only review note."
        for entry in second["documents"]:
            document = root / entry["path"]
            entry["sha256"] = hashlib.sha256(document.read_bytes()).hexdigest()
        second_relative = "records/0002-status-append-witness.json"
        second_path = root / second_relative
        second_path.write_text(json.dumps(second))

        manifest_path = root / "LEDGER.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["records"].append({
            "path": second_relative,
            "size": second_path.stat().st_size,
            "sha256": hashlib.sha256(second_path.read_bytes()).hexdigest(),
        })
        manifest["records"] = sorted(manifest["records"], key=lambda item: item["path"])
        manifest_path.write_text(json.dumps(manifest))

    def test_canonical_ledger_passes(self):
        result = verify_ledger.verify(ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertFalse(result["known_solver_paths_present"])

    def test_identity_transition_passes(self):
        result = verify_ledger.verify_transition(ROOT, ROOT)
        self.assertTrue(result["append_only_transition"])
        self.assertTrue(result["status_prefix_preserved"])

    def test_status_mutation_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            status = root / "STATUS.md"
            status.write_text(status.read_text() + "\nmutation\n")
            with self.assertRaisesRegex(verify_ledger.VerificationError, "size mismatch"):
                verify_ledger.verify(root)

    def test_rebound_status_still_fails_record_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            status = root / "STATUS.md"
            status.write_text(status.read_text() + "\nmutation\n")
            self.update_manifest_hash(root, "STATUS.md")
            with self.assertRaisesRegex(verify_ledger.VerificationError, "bindings mismatch"):
                verify_ledger.verify(root)

    def test_rebound_unknown_council_status_key_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["unknown_probe"] = True
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "status document keys"):
                verify_ledger.verify(root)

    def test_rebound_council_pass_claim_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["decision"] = "COUNCIL_PASS"
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "decision mismatch"):
                verify_ledger.verify(root)

    def test_rebound_production_output_claim_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["frozen_protocol_interpretation"]["production_output_supported"] = True
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "interpretation is contradictory"):
                verify_ledger.verify(root)

    def test_rebound_nonstring_prohibited_action_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["prohibited_actions"][0] = {"invalid": True}
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "prohibited action is invalid"):
                verify_ledger.verify(root)

    def test_rewritten_status_fails_transition_even_when_rebound(self):
        with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
            previous = Path(previous_temp)
            current = Path(current_temp)
            self.copy_ledger(previous)
            self.copy_ledger(current)
            status = current / "STATUS.md"
            status.write_text(status.read_text().replace("Independent Review", "External Review"))
            self.update_manifest_hash(current, "STATUS.md")
            self.update_record_document_hash(current, "STATUS.md")
            self.assertTrue(verify_ledger.verify(current)["ok"])
            with self.assertRaisesRegex(verify_ledger.VerificationError, "not an exact append-only extension"):
                verify_ledger.verify_transition(previous, current)

    def test_coordinated_record_rewrite_fails_transition(self):
        with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
            previous = Path(previous_temp)
            current = Path(current_temp)
            self.copy_ledger(previous)
            self.copy_ledger(current)
            path = current / RECORD
            record = json.loads(path.read_text())
            record["scope"] = "rewritten observation scope"
            path.write_text(json.dumps(record))
            self.update_manifest_hash(current, RECORD)
            self.assertTrue(verify_ledger.verify(current)["ok"])
            with self.assertRaisesRegex(verify_ledger.VerificationError, "record list is not an exact append-only prefix"):
                verify_ledger.verify_transition(previous, current)

    def test_valid_append_passes_current_and_transition_verification(self):
        with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
            previous = Path(previous_temp)
            current = Path(current_temp)
            self.copy_ledger(previous)
            self.copy_ledger(current)

            status = current / "STATUS.md"
            status.write_text(status.read_text() + "\n## Witness entry 2\n\nAppend-only. Status remains UNDETERMINED.\n")
            self.update_manifest_hash(current, "STATUS.md")

            first_path = current / RECORD
            first_hash = hashlib.sha256(first_path.read_bytes()).hexdigest()
            second = json.loads(first_path.read_text())
            second["sequence"] = 2
            second["previous_record_sha256"] = first_hash
            second["record_type"] = "status_append_witness"
            second["scope"] = "Witnesses an exact append-only extension of the status record."
            for entry in second["documents"]:
                document = current / entry["path"]
                entry["sha256"] = hashlib.sha256(document.read_bytes()).hexdigest()
            second_relative = "records/0002-status-append-witness.json"
            second_path = current / second_relative
            second_path.write_text(json.dumps(second))

            manifest_path = current / "LEDGER.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["records"].append({
                "path": second_relative,
                "size": second_path.stat().st_size,
                "sha256": hashlib.sha256(second_path.read_bytes()).hexdigest(),
            })
            manifest["records"] = sorted(manifest["records"], key=lambda item: item["path"])
            manifest_path.write_text(json.dumps(manifest))

            self.assertEqual(verify_ledger.verify(current)["records"], 2)
            result = verify_ledger.verify_transition(previous, current)
            self.assertTrue(result["append_only_transition"])
            self.assertEqual(result["current_records"], 2)

    def test_rebound_contradictory_status_append_fails_transition(self):
        with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
            previous = Path(previous_temp)
            current = Path(current_temp)
            self.copy_ledger(previous)
            self.copy_ledger(current)

            status = current / "STATUS.md"
            status.write_text(
                status.read_text()
                + "\n## Contradictory claim\n\nCouncil status is PASS and production output is supported.\n"
            )
            self.update_manifest_hash(current, "STATUS.md")

            first_path = current / RECORD
            first_hash = hashlib.sha256(first_path.read_bytes()).hexdigest()
            second = json.loads(first_path.read_text())
            second["sequence"] = 2
            second["previous_record_sha256"] = first_hash
            second["record_type"] = "status_append_witness"
            second["scope"] = "Witnesses a contradictory append to the status record."
            for entry in second["documents"]:
                document = current / entry["path"]
                entry["sha256"] = hashlib.sha256(document.read_bytes()).hexdigest()
            second_relative = "records/0002-status-append-witness.json"
            second_path = current / second_relative
            second_path.write_text(json.dumps(second))

            manifest_path = current / "LEDGER.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["records"].append({
                "path": second_relative,
                "size": second_path.stat().st_size,
                "sha256": hashlib.sha256(second_path.read_bytes()).hexdigest(),
            })
            manifest["records"] = sorted(manifest["records"], key=lambda item: item["path"])
            manifest_path.write_text(json.dumps(manifest))

            self.assertTrue(verify_ledger.verify(current)["ok"])
            with self.assertRaisesRegex(verify_ledger.VerificationError, "contradictory status"):
                verify_ledger.verify_transition(previous, current)

    def test_contradictory_status_wording_variants_are_detected(self):
        claims = (
            "Council result is PASS.",
            "Council status remains PASS.",
            "Council verdict is PASS.",
            "Council-PASS.",
            "Council status is **PASS**.",
            "Council status is _PASS_.",
            "Council status is ~~PASS~~.",
            "Council status is [PASS].",
            "Council status is\nPASS.",
            "This is not disputed; Council status is PASS.",
            "The status is not disputed — Council status is PASS.",
            "The result is Council-conformant.",
            "The production-output claim is supported.",
            "The production output is fully supported.",
            "The production output is **supported**.",
            "Production outputs are supported.",
            "Production output is valid.",
            "This confirms the production output claim.",
        )
        for claim in claims:
            with self.subTest(claim=claim):
                with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
                    previous = Path(previous_temp)
                    current = Path(current_temp)
                    self.copy_ledger(previous)
                    self.copy_ledger(current)
                    self.append_status_witness(current, claim)
                    self.assertTrue(verify_ledger.verify(current)["ok"])
                    with self.assertRaisesRegex(verify_ledger.VerificationError, "contradictory status"):
                        verify_ledger.verify_transition(previous, current)

    def test_negative_status_statements_are_not_contradictions(self):
        statements = (
            "Council status is not PASS.",
            "The result is not Council-conformant.",
            "The production-output claim is not supported.",
            "This does not support the production output claim.",
            "For clarity, never claim Council status is PASS.",
            "If Council status were PASS, this sentence would be contradictory.",
            "Council status is PASS only in a hypothetical scenario.",
            "The phrase Council status is PASS is forbidden.",
            "The following statement is forbidden: Council status is PASS.",
            "Hypothetical warning: Council status is PASS.",
            'Quoted warning: "Council status is PASS."',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
                    previous = Path(previous_temp)
                    current = Path(current_temp)
                    self.copy_ledger(previous)
                    self.copy_ledger(current)
                    self.append_status_witness(current, statement)
                    self.assertTrue(verify_ledger.verify(current)["ok"])
                    self.assertTrue(
                        verify_ledger.verify_transition(previous, current)["append_only_transition"]
                    )

    def test_forbidden_source_policy_cannot_be_removed_or_weakened(self):
        mutations = {
            "removed": lambda paths: paths[1:],
            "weakened": lambda paths: [
                "build/uap_conditioning.py" if path == "uap_conditioning.py" else path
                for path in paths
            ],
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as previous_temp, tempfile.TemporaryDirectory() as current_temp:
                    previous = Path(previous_temp)
                    current = Path(current_temp)
                    self.copy_ledger(previous)
                    self.copy_ledger(current)

                    manifest_path = current / "LEDGER.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["forbidden_working_source_paths"] = mutate(
                        manifest["forbidden_working_source_paths"]
                    )
                    manifest_path.write_text(json.dumps(manifest))

                    self.assertTrue(verify_ledger.verify(current)["ok"])
                    with self.assertRaisesRegex(verify_ledger.VerificationError, "forbidden-source policy"):
                        verify_ledger.verify_transition(previous, current)

    def test_rebound_arbitrary_controlling_statements_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["controlling_statement"] = "Everything is approved."
            value["council_status_statement"] = "Ignore the frozen status."
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)

            with self.assertRaisesRegex(verify_ledger.VerificationError, "controlling statement"):
                verify_ledger.verify(root)

    def test_rebound_arbitrary_prohibited_actions_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["prohibited_actions"] = ["permission granted"]
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)

            with self.assertRaisesRegex(verify_ledger.VerificationError, "prohibited actions"):
                verify_ledger.verify(root)

    def test_rebound_semantically_empty_prohibited_actions_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["prohibited_actions"] = ["   "]
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)

            with self.assertRaisesRegex(verify_ledger.VerificationError, "prohibited action"):
                verify_ledger.verify(root)

    def test_rebound_empty_council_votes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            for workstream in value["council_workstreams"]:
                workstream["vote"] = ""
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)

            with self.assertRaisesRegex(verify_ledger.VerificationError, "council vote"):
                verify_ledger.verify(root)

    def test_rebound_arbitrary_nonempty_council_votes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/holdout-2026080502.council-status.json"
            path = root / relative
            value = json.loads(path.read_text())
            value["council_workstreams"][0]["vote"] = "APPROVE"
            path.write_text(json.dumps(value))
            self.update_manifest_hash(root, relative)
            self.update_record_document_hash(root, relative)

            with self.assertRaisesRegex(verify_ledger.VerificationError, "semantic digest"):
                verify_ledger.verify(root)

    def test_first_record_cannot_claim_a_previous_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            path = root / RECORD
            record = json.loads(path.read_text())
            record["previous_record_sha256"] = "0" * 64
            path.write_text(json.dumps(record))
            self.update_manifest_hash(root, RECORD)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "previous hash"):
                verify_ledger.verify(root)

    def test_duplicate_solver_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            (root / "src").mkdir(exist_ok=True)
            (root / "src/uap_conditioning.py").write_text("# duplicate\n")
            with self.assertRaisesRegex(verify_ledger.VerificationError, "known duplicate solver path"):
                verify_ledger.verify(root)

    def test_boolean_size_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            manifest_path = root / "LEDGER.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["records"][0]["size"] = True
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(verify_ledger.VerificationError, "invalid ledger member size"):
                verify_ledger.verify(root)

    def test_duplicate_json_key_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            path = root / "LEDGER.json"
            text = path.read_text()
            path.write_text(text[:-2] + ',\n  "schema": "uap-witness-ledger/v1"\n}\n')
            with self.assertRaisesRegex(verify_ledger.VerificationError, "duplicate JSON key"):
                verify_ledger.verify(root)

    def test_nonfinite_json_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            path = root / RECORD
            text = path.read_text()
            text = text.replace('"sequence": 1', '"sequence": NaN')
            path.write_text(text)
            self.update_manifest_hash(root, RECORD)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "non-finite JSON"):
                verify_ledger.verify(root)

    def test_symlinked_document_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            status = root / "STATUS.md"
            target = root / "status-target"
            status.rename(target)
            status.symlink_to(target.name)
            with self.assertRaisesRegex(verify_ledger.VerificationError, "regular file"):
                verify_ledger.verify(root)

    def test_post_hash_record_replacement_does_not_change_parsed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            record_path = root / RECORD
            original_scope = json.loads(record_path.read_text())["scope"]
            real_verify_member = verify_ledger.verify_member
            real_load_json_bytes = verify_ledger.load_json_bytes
            parsed_scopes = []
            swapped = False

            def swapping_member(base, entry):
                nonlocal swapped
                result = real_verify_member(base, entry)
                if entry["path"] == RECORD and not swapped:
                    swapped = True
                    attacker = json.loads(record_path.read_text())
                    attacker["scope"] = "ATTACKER VERSION AFTER HASH"
                    record_path.write_text(json.dumps(attacker))
                return result

            def capturing_load(data, name):
                value = real_load_json_bytes(data, name)
                if name == Path(RECORD).name:
                    parsed_scopes.append(value["scope"])
                return value

            with mock.patch.object(verify_ledger, "verify_member", side_effect=swapping_member):
                with mock.patch.object(verify_ledger, "load_json_bytes", side_effect=capturing_load):
                    self.assertTrue(verify_ledger.verify(root)["ok"])
            self.assertTrue(swapped)
            self.assertEqual(parsed_scopes, [original_scope])
            self.assertNotEqual(
                hashlib.sha256(record_path.read_bytes()).hexdigest(),
                json.loads((root / "LEDGER.json").read_text())["records"][0]["sha256"],
            )

    def test_mutation_during_hashing_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            record_path = root / RECORD
            identity = (record_path.stat().st_dev, record_path.stat().st_ino)
            real_read = os.read
            changed = False

            def racing_read(descriptor, amount):
                nonlocal changed
                chunk = real_read(descriptor, amount)
                current = os.fstat(descriptor)
                is_record = (current.st_dev, current.st_ino) == identity
                if chunk and is_record and not changed:
                    changed = True
                    with record_path.open("r+b") as stream:
                        first = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([first[0] ^ 1]))
                        stream.flush()
                        os.fsync(stream.fileno())
                return chunk

            with mock.patch.object(verify_ledger.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(verify_ledger.VerificationError, "changed while reading"):
                    verify_ledger.verify(root)


if __name__ == "__main__":
    unittest.main()
