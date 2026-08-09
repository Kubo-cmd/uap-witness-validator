import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify_ledger


ROOT = Path(__file__).resolve().parents[1]


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

    def test_canonical_ledger_passes(self):
        result = verify_ledger.verify(ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertFalse(result["solver_source_present"])

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

    def test_first_record_cannot_claim_a_previous_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_ledger(root)
            relative = "records/0001-release-status-witness.json"
            path = root / relative
            record = json.loads(path.read_text())
            record["previous_record_sha256"] = "0" * 64
            path.write_text(json.dumps(record))
            self.update_manifest_hash(root, relative)
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


if __name__ == "__main__":
    unittest.main()
