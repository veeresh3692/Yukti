from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import RecoveryArtifact, VerificationResult


class ReportingService:
    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        name: str,
        actor: str,
        drive_result: VerificationResult | None = None,
        file_results: list[VerificationResult] | None = None,
        artifacts: list[RecoveryArtifact] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Path:
        payload = {
            "actor": actor,
            "drive_result": asdict(drive_result) if drive_result else None,
            "file_results": [asdict(result) for result in (file_results or [])],
            "recovery_artifacts": [asdict(artifact) for artifact in (artifacts or [])],
            "extra": extra or {},
        }
        body = json.dumps(payload, sort_keys=True, indent=2)
        signature = hashlib.sha256(body.encode("utf-8")).hexdigest()
        report = {"payload": payload, "tamper_evident_signature": signature}
        report_path = self.reports_dir / f"{name}.json"
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
        return report_path

    def verify_report(self, report_path: Path) -> bool:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        payload_blob = json.dumps(report["payload"], sort_keys=True, indent=2)
        expected = hashlib.sha256(payload_blob.encode("utf-8")).hexdigest()
        return expected == report["tamper_evident_signature"]
