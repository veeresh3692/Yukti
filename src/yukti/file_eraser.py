from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .audit import AuditLogger
from .erasure_profiles import ERASURE_PROFILES
from .models import VerificationResult


class SecureFileFolderEraser:
    def __init__(self, audit_logger: AuditLogger) -> None:
        self.audit_logger = audit_logger

    def erase_paths(self, paths: Iterable[Path], profile_name: str, actor: str) -> list[VerificationResult]:
        if profile_name not in ERASURE_PROFILES:
            raise ValueError(f"Unknown erasure profile: {profile_name}")
        profile = ERASURE_PROFILES[profile_name]
        results: list[VerificationResult] = []
        for path in paths:
            if path.is_dir():
                for child in sorted(path.rglob("*"), reverse=True):
                    if child.is_file():
                        results.append(self._erase_file(child, profile.passes, actor, profile.standard))
                for child in sorted(path.rglob("*"), reverse=True):
                    if child.is_dir():
                        child.rmdir()
                path.rmdir()
                self.audit_logger.log(actor=actor, action="folder_removed", context={"path": str(path)})
            elif path.is_file():
                results.append(self._erase_file(path, profile.passes, actor, profile.standard))
        return results

    def _erase_file(self, path: Path, passes: int, actor: str, standard: str) -> VerificationResult:
        size = path.stat().st_size
        with path.open("r+b") as fh:
            for pass_index in range(passes):
                fh.seek(0)
                fh.write(bytes([(pass_index + 7) % 256]) * size)
                fh.flush()
                os.fsync(fh.fileno())
                self.audit_logger.log(
                    actor=actor,
                    action="file_erase_pass",
                    context={"path": str(path), "pass": pass_index + 1, "standard": standard},
                )
            fh.seek(0)
            data = fh.read(min(size, 4096))
        expected = bytes([(passes + 6) % 256]) * len(data)
        verification = data == expected

        path.unlink()
        self.audit_logger.log(actor=actor, action="file_removed", context={"path": str(path), "size": size})

        result = VerificationResult(
            success=verification and not path.exists(),
            method="secure_file_erase",
            evidence={"path": str(path), "size": size, "passes": passes},
        )
        self.audit_logger.log(actor=actor, action="file_erase_verification", context={"result": result.success, **result.evidence})
        return result
