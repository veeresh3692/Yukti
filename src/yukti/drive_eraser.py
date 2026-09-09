from __future__ import annotations

from pathlib import Path

from .audit import AuditLogger
from .erasure_profiles import ERASURE_PROFILES
from .models import VerificationResult


class SecureDriveEraser:
    def __init__(self, audit_logger: AuditLogger, chunk_size: int = 1024 * 1024) -> None:
        self.audit_logger = audit_logger
        self.chunk_size = chunk_size

    def erase(self, device_path: Path, profile_name: str, actor: str) -> VerificationResult:
        if profile_name not in ERASURE_PROFILES:
            raise ValueError(f"Unknown erasure profile: {profile_name}")
        profile = ERASURE_PROFILES[profile_name]
        if not device_path.exists() or not device_path.is_file():
            raise ValueError("Device path must be a writable file in this reference implementation.")

        size = device_path.stat().st_size
        for pass_index in range(profile.passes):
            pattern = bytes([(pass_index + 1) % 256]) * min(self.chunk_size, max(size, 1))
            written = 0
            with device_path.open("r+b") as fh:
                while written < size:
                    remaining = size - written
                    block = pattern[: min(remaining, len(pattern))]
                    fh.write(block)
                    written += len(block)
                fh.flush()
            self.audit_logger.log(
                actor=actor,
                action="drive_erase_pass",
                context={"device_path": str(device_path), "pass": pass_index + 1, "standard": profile.standard},
            )

        if size:
            with device_path.open("rb") as fh:
                tail = fh.read(min(size, 4096))
            expected = bytes([profile.passes % 256]) * len(tail)
            success = tail == expected
        else:
            success = True

        result = VerificationResult(
            success=success,
            method=f"profile:{profile_name}",
            evidence={"device_path": str(device_path), "size": size, "passes": profile.passes, "standard": profile.standard},
        )
        self.audit_logger.log(actor=actor, action="drive_erase_verification", context={"result": result.success, **result.evidence})
        return result
