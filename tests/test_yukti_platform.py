import json
import tempfile
import unittest
from pathlib import Path

from yukti.platform import YuktiPlatform


class YuktiPlatformTests(unittest.TestCase):
    def test_secure_file_folder_erase_removes_target_and_logs(self) -> None:
        app = YuktiPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sensitive.txt"
            target.write_bytes(b"top-secret-data")
            result = app.secure_erase_files_folders([str(target)], passes=2)

            self.assertEqual(result.summary["targets_erased"], 1)
            self.assertFalse(target.exists())
            self.assertTrue(app.audit_logger.validate_chain())
            self.assertEqual(len(app.audit_logger.entries), 1)

    def test_secure_drive_erase_erases_files_under_mount(self) -> None:
        app = YuktiPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / "drive"
            (mount / "nested").mkdir(parents=True)
            (mount / "a.bin").write_bytes(b"A" * 32)
            (mount / "nested" / "b.bin").write_bytes(b"B" * 32)

            result = app.secure_erase_drive(str(mount), passes=1)
            self.assertEqual(result.summary["files_discovered"], 2)
            self.assertEqual(result.summary["files_erased"], 2)
            self.assertFalse((mount / "a.bin").exists())
            self.assertFalse((mount / "nested" / "b.bin").exists())

    def test_advanced_recovery_carves_and_classifies(self) -> None:
        app = YuktiPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            media = Path(tmp) / "disk.img"
            png = b"\x89PNG\r\n\x1a\nDATAIEND\xaeB`\x82"
            pdf = b"%PDF-1.7\nobj\n%%EOF"
            media.write_bytes(b"xx" + png + b"yy" + pdf + b"zz")

            result = app.recover_from_media(str(media))
            self.assertGreaterEqual(result.summary["recovered_count"], 2)
            self.assertTrue(any(f["extension"] == "png" for f in result.findings))
            self.assertTrue(any(f["extension"] == "pdf" for f in result.findings))
            self.assertTrue(all(0.0 <= f["confidence_score"] <= 1.0 for f in result.findings))

    def test_forensic_report_contains_tamper_status(self) -> None:
        app = YuktiPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secret.bin"
            target.write_bytes(b"123")
            app.secure_erase_files_folders([str(target)])
            report = app.forensic_report()

            self.assertTrue(report.summary["hash_chain_valid"])
            self.assertTrue(report.summary["tamper_resistant_reporting"])
            rendered = json.dumps(report.to_dict())
            self.assertIn("forensic_audit_report", rendered)


if __name__ == "__main__":
    unittest.main()
