from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .audit import AuditLogger
from .drive_eraser import SecureDriveEraser
from .file_eraser import SecureFileFolderEraser
from .recovery import AdvancedRecoveryEngine
from .reporting import ReportingService


class YuktiPlatform:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.audit_logger = AuditLogger(workspace / "audit" / "audit.log")
        self.drive_eraser = SecureDriveEraser(self.audit_logger)
        self.file_eraser = SecureFileFolderEraser(self.audit_logger)
        self.recovery = AdvancedRecoveryEngine(self.audit_logger)
        self.reporting = ReportingService(workspace / "reports")

    def sanitize_drive(self, device_path: Path, profile: str, actor: str):
        result = self.drive_eraser.erase(device_path=device_path, profile_name=profile, actor=actor)
        report = self.reporting.generate_report(name="drive_sanitization", actor=actor, drive_result=result, extra={"profile": profile})
        return result, report

    def sanitize_files(self, paths: Iterable[Path], profile: str, actor: str):
        results = self.file_eraser.erase_paths(paths=paths, profile_name=profile, actor=actor)
        report = self.reporting.generate_report(name="file_sanitization", actor=actor, file_results=results, extra={"profile": profile})
        return results, report

    def recover(self, image_path: Path, output_dir: Path, actor: str):
        chain = self.recovery.acquire_read_only(image_path=image_path, actor=actor)
        artifacts = self.recovery.carve(image_path=image_path, output_dir=output_dir, actor=actor)
        grouped = self.recovery.classify(artifacts)
        report = self.reporting.generate_report(
            name="forensic_recovery",
            actor=actor,
            artifacts=artifacts,
            extra={"chain_of_custody": chain.details, "classification_counts": {k: len(v) for k, v in grouped.items()}},
        )
        return artifacts, report
