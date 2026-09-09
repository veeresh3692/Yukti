from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Iterable, List, Tuple

from .audit import AuditLogger
from .models import OperationReport


def _scrub_name(path: Path) -> Path:
    token = secrets.token_hex(8)
    return path.with_name(f".wipe_{token}")


class SecureFileFolderEraser:
    def __init__(self, logger: AuditLogger) -> None:
        self.logger = logger

    def _overwrite(self, path: Path, passes: int) -> int:
        size = path.stat().st_size
        if size == 0:
            return 0
        with path.open("r+b") as handle:
            for idx in range(max(1, passes)):
                handle.seek(0)
                pattern = os.urandom(size) if idx < passes - 1 else b"\x00" * size
                handle.write(pattern)
                handle.flush()
                os.fsync(handle.fileno())
        return size

    def _erase_file(self, path: Path, passes: int) -> Tuple[bool, int, str]:
        overwritten = self._overwrite(path, passes=passes)
        scrubbed = _scrub_name(path)
        path.rename(scrubbed)
        scrubbed.unlink(missing_ok=False)
        verified = not scrubbed.exists() and not path.exists()
        return verified, overwritten, str(scrubbed)

    def erase_paths(self, targets: Iterable[str], passes: int = 3) -> OperationReport:
        target_list = list(targets)
        findings: List[dict] = []
        erased_count = 0
        failed_count = 0
        for target in target_list:
            p = Path(target).expanduser().resolve()
            try:
                if not p.exists():
                    raise FileNotFoundError(f"{p} does not exist")
                if p.is_file():
                    verified, overwritten, scrubbed = self._erase_file(p, passes=passes)
                    findings.append(
                        {
                            "target": str(p),
                            "type": "file",
                            "verified": verified,
                            "bytes_overwritten": overwritten,
                            "scrubbed_name": scrubbed,
                        }
                    )
                    erased_count += 1
                else:
                    child_files = sorted([f for f in p.rglob("*") if f.is_file()], reverse=True)
                    bytes_overwritten = 0
                    for file_path in child_files:
                        verified, overwritten, _ = self._erase_file(file_path, passes=passes)
                        if not verified:
                            raise RuntimeError(f"Could not verify erasure of {file_path}")
                        bytes_overwritten += overwritten
                    for dir_path in sorted([d for d in p.rglob("*") if d.is_dir()], reverse=True):
                        dir_path.rmdir()
                    scrubbed_root = _scrub_name(p)
                    p.rename(scrubbed_root)
                    scrubbed_root.rmdir()
                    verified = not p.exists() and not scrubbed_root.exists()
                    findings.append(
                        {
                            "target": str(p),
                            "type": "folder",
                            "verified": verified,
                            "bytes_overwritten": bytes_overwritten,
                        }
                    )
                    erased_count += 1

                self.logger.log(
                    module="secure_file_folder_eraser",
                    operation="erase_paths",
                    target=str(p),
                    status="success",
                    details=findings[-1],
                )
            except Exception as exc:  # defensive audit trail
                failed_count += 1
                detail = {"target": str(p), "error": str(exc)}
                findings.append(detail)
                self.logger.log(
                    module="secure_file_folder_eraser",
                    operation="erase_paths",
                    target=str(p),
                    status="failed",
                    details=detail,
                )

        return OperationReport(
            report_type="secure_file_folder_erase",
            summary={
                "targets_requested": len(target_list),
                "targets_erased": erased_count,
                "targets_failed": failed_count,
                "passes": passes,
            },
            findings=findings,
        )


class SecureDriveEraser:
    def __init__(self, logger: AuditLogger) -> None:
        self.logger = logger
        self._eraser = SecureFileFolderEraser(logger=logger)

    def erase_drive(self, mount_path: str, passes: int = 3) -> OperationReport:
        path = Path(mount_path).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Drive path {path} does not exist or is not a directory")
        if str(path) == "/":
            raise ValueError("Refusing to erase system root")

        findings: List[dict] = []
        files = [f for f in path.rglob("*") if f.is_file()]
        erased = 0
        failed = 0
        for f in files:
            try:
                verified, overwritten, scrubbed = self._eraser._erase_file(f, passes=passes)
                erased += 1
                item = {
                    "target": str(f),
                    "verified": verified,
                    "bytes_overwritten": overwritten,
                    "scrubbed_name": scrubbed,
                }
                findings.append(item)
                self.logger.log(
                    module="secure_drive_eraser",
                    operation="erase_drive",
                    target=str(f),
                    status="success",
                    details=item,
                )
            except Exception as exc:  # defensive audit trail
                failed += 1
                item = {"target": str(f), "error": str(exc)}
                findings.append(item)
                self.logger.log(
                    module="secure_drive_eraser",
                    operation="erase_drive",
                    target=str(f),
                    status="failed",
                    details=item,
                )

        # Keep mount path but clean empty directories under it.
        for d in sorted([d for d in path.rglob("*") if d.is_dir()], reverse=True):
            try:
                d.rmdir()
            except OSError:
                pass

        return OperationReport(
            report_type="secure_drive_erase",
            summary={
                "mount_path": str(path),
                "files_discovered": len(files),
                "files_erased": erased,
                "files_failed": failed,
                "passes": passes,
                "verification": "path non-existence check post wipe",
            },
            findings=findings,
        )
