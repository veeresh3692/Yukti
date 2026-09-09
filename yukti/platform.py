from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .audit import AuditLogger
from .eraser import SecureDriveEraser, SecureFileFolderEraser
from .models import OperationReport
from .recovery import AdvancedFileCarver


class YuktiPlatform:
    """Integrated platform for secure erasure and forensic recovery."""

    def __init__(self) -> None:
        self.audit_logger = AuditLogger()
        self.drive_eraser = SecureDriveEraser(logger=self.audit_logger)
        self.file_folder_eraser = SecureFileFolderEraser(logger=self.audit_logger)
        self.file_carver = AdvancedFileCarver(logger=self.audit_logger)

    def secure_erase_drive(self, mount_path: str, passes: int = 3) -> OperationReport:
        return self.drive_eraser.erase_drive(mount_path=mount_path, passes=passes)

    def secure_erase_files_folders(self, targets: Iterable[str], passes: int = 3) -> OperationReport:
        return self.file_folder_eraser.erase_paths(targets=targets, passes=passes)

    def recover_from_media(self, media_path: str, output_dir: Optional[str] = None) -> OperationReport:
        return self.file_carver.recover(media_path=media_path, output_dir=output_dir)

    def forensic_report(self) -> OperationReport:
        return OperationReport(
            report_type="forensic_audit_report",
            summary={
                "total_audit_entries": len(self.audit_logger.entries),
                "hash_chain_valid": self.audit_logger.validate_chain(),
                "tamper_resistant_reporting": True,
            },
            findings=[],
            audit_trail=self.audit_logger.export(),
        )

    def export_report(self, report: OperationReport, output_path: str) -> str:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return str(out.resolve())
