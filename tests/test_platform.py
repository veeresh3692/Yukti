from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yukti.audit import AuditLogger
from yukti.orchestrator import YuktiPlatform
from yukti.reporting import ReportingService


class YuktiPlatformTests(unittest.TestCase):
    def test_drive_sanitization_and_report_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            device = base / "device.img"
            device.write_bytes(b"A" * 4096)

            platform = YuktiPlatform(base / "workspace")
            result, report_path = platform.sanitize_drive(device, "clear", "tester")

            self.assertTrue(result.success)
            self.assertTrue(report_path.exists())
            self.assertTrue(platform.reporting.verify_report(report_path))
            self.assertTrue(platform.audit_logger.verify_chain())

    def test_file_batch_erase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target_dir = base / "targets"
            target_dir.mkdir()
            (target_dir / "a.txt").write_text("secret", encoding="utf-8")
            (target_dir / "b.txt").write_text("secret2", encoding="utf-8")

            platform = YuktiPlatform(base / "workspace")
            results, _ = platform.sanitize_files([target_dir], "clear", "tester")

            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.success for item in results))
            self.assertFalse(target_dir.exists())
            self.assertTrue(platform.audit_logger.verify_chain())

    def test_recovery_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            image = base / "raw.bin"
            png_payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"IEND\xaeB`\x82"
            pdf_payload = b"%PDF-1.4\nbody\n%%EOF"
            image.write_bytes(b"xxxx" + png_payload + b"yyyy" + pdf_payload + b"zzzz")

            platform = YuktiPlatform(base / "workspace")
            artifacts, report = platform.recover(image, base / "out", "tester")
            report_obj = json.loads(report.read_text(encoding="utf-8"))

            self.assertGreaterEqual(len(artifacts), 2)
            self.assertIn("tamper_evident_signature", report_obj)
            self.assertTrue(platform.reporting.verify_report(report))
            self.assertTrue(platform.audit_logger.verify_chain())


class ReportingServiceTests(unittest.TestCase):
    def test_report_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = ReportingService(Path(tmp))
            report = reports.generate_report(name="x", actor="tester")
            self.assertTrue(reports.verify_report(report))

            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["payload"]["extra"]["tampered"] = True
            report.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
            self.assertFalse(reports.verify_report(report))


class AuditLoggerTests(unittest.TestCase):
    def test_chain_break_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            logger = AuditLogger(log_path)
            logger.log(actor="a", action="one", context={})
            logger.log(actor="a", action="two", context={})
            self.assertTrue(logger.verify_chain())

            lines = log_path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[1])
            entry["action"] = "tampered"
            lines[1] = json.dumps(entry)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(logger.verify_chain())


if __name__ == "__main__":
    unittest.main()
