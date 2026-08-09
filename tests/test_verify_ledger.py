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

    def test_canonical_ledger_passes(self):
        result = verify_ledger.verify(ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertFalse(result["solver_source_present"])

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
            with self.assertRaisesRegex(verify_ledger.VerificationError, "duplicate solver"):
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
