from __future__ import annotations

import hashlib
from pathlib import Path

from .audit import AuditLogger
from .models import ChainOfCustodyRecord, RecoveryArtifact

SIGNATURES: dict[str, tuple[bytes, bytes | None]] = {
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    "jpg": (b"\xff\xd8\xff", b"\xff\xd9"),
    "pdf": (b"%PDF", b"%%EOF"),
    "zip": (b"PK\x03\x04", b"PK\x05\x06"),
}


class AdvancedRecoveryEngine:
    def __init__(self, audit_logger: AuditLogger) -> None:
        self.audit_logger = audit_logger

    def acquire_read_only(self, image_path: Path, actor: str) -> ChainOfCustodyRecord:
        raw = image_path.read_bytes()
        checksum = hashlib.sha256(raw).hexdigest()
        record = ChainOfCustodyRecord(action="acquire_read_only", actor=actor, details={"path": str(image_path), "sha256": checksum})
        self.audit_logger.log(actor=actor, action=record.action, context=record.details)
        return record

    def carve(self, image_path: Path, output_dir: Path, actor: str) -> list[RecoveryArtifact]:
        output_dir.mkdir(parents=True, exist_ok=True)
        data = image_path.read_bytes()
        artifacts: list[RecoveryArtifact] = []
        for file_type, (header, footer) in SIGNATURES.items():
            start = 0
            hit = 0
            while True:
                index = data.find(header, start)
                if index == -1:
                    break
                if footer:
                    end = data.find(footer, index + len(header))
                    if end == -1:
                        fragment = data[index : index + min(2048, len(data) - index)]
                        confidence = 0.55
                        method = "signature_fragment"
                    else:
                        end += len(footer)
                        fragment = data[index:end]
                        confidence = 0.9
                        method = "signature_complete"
                else:
                    fragment = data[index : index + min(4096, len(data) - index)]
                    confidence = 0.6
                    method = "structure_based"
                file_path = output_dir / f"carved_{file_type}_{hit}.{file_type}"
                file_path.write_bytes(fragment)
                artifact = RecoveryArtifact(
                    path=str(file_path),
                    file_type=file_type,
                    confidence=confidence,
                    method=method,
                    metadata={"offset": index, "size": len(fragment), "sha256": hashlib.sha256(fragment).hexdigest()},
                )
                artifacts.append(artifact)
                self.audit_logger.log(actor=actor, action="artifact_recovered", context=artifact.metadata | {"path": artifact.path, "type": artifact.file_type})
                hit += 1
                start = index + len(header)
        return artifacts

    def classify(self, artifacts: list[RecoveryArtifact]) -> dict[str, list[RecoveryArtifact]]:
        buckets: dict[str, list[RecoveryArtifact]] = {}
        for artifact in artifacts:
            buckets.setdefault(artifact.file_type, []).append(artifact)
        return buckets
