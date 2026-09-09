from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .audit import AuditLogger
from .models import OperationReport, RecoveredFile


@dataclass(frozen=True)
class Signature:
    extension: str
    category: str
    header: bytes
    footer: Optional[bytes] = None


class AdvancedFileCarver:
    def __init__(self, logger: AuditLogger) -> None:
        self.logger = logger
        self.signatures: List[Signature] = [
            Signature("png", "image", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
            Signature("jpg", "image", b"\xff\xd8", b"\xff\xd9"),
            Signature("pdf", "document", b"%PDF", b"%%EOF"),
            Signature("zip", "archive", b"PK\x03\x04", None),
        ]

    def _score(self, file_bytes: bytes, has_footer: bool) -> float:
        score = 0.4
        if has_footer:
            score += 0.3
        if len(file_bytes) > 32:
            score += 0.2
        uniq_ratio = len(set(file_bytes[: min(256, len(file_bytes))])) / max(1, min(256, len(file_bytes)))
        if 0.05 < uniq_ratio < 0.95:
            score += 0.1
        return min(1.0, max(0.0, score))

    def carve(self, media_bytes: bytes) -> List[RecoveredFile]:
        recovered: List[RecoveredFile] = []
        idx = 0
        for sig in self.signatures:
            start = 0
            while True:
                start = media_bytes.find(sig.header, start)
                if start == -1:
                    break

                has_footer = False
                if sig.footer:
                    footer_at = media_bytes.find(sig.footer, start + len(sig.header))
                    if footer_at != -1:
                        end = footer_at + len(sig.footer)
                        has_footer = True
                    else:
                        end = min(len(media_bytes), start + 4096)
                else:
                    # Heuristic for metadata-less carving.
                    next_offset = len(media_bytes)
                    for other in self.signatures:
                        if other.header == sig.header:
                            continue
                        n = media_bytes.find(other.header, start + len(sig.header))
                        if n != -1:
                            next_offset = min(next_offset, n)
                    end = max(start + len(sig.header), next_offset)

                file_bytes = media_bytes[start:end]
                digest = hashlib.sha256(file_bytes).hexdigest()
                confidence = self._score(file_bytes, has_footer=has_footer)
                idx += 1
                recovered.append(
                    RecoveredFile(
                        file_name=f"recovered_{idx}.{sig.extension}",
                        extension=sig.extension,
                        category=sig.category,
                        confidence_score=confidence,
                        start_offset=start,
                        end_offset=end,
                        sha256=digest,
                        size=len(file_bytes),
                        metadata_based=False,
                    )
                )
                start += len(sig.header)
        return sorted(recovered, key=lambda item: item.start_offset)

    def recover(self, media_path: str, output_dir: Optional[str] = None) -> OperationReport:
        data = Path(media_path).read_bytes()
        recovered = self.carve(data)

        findings: List[Dict[str, object]] = [item.to_dict() for item in recovered]
        output_written = 0
        if output_dir:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            for item in recovered:
                chunk = data[item.start_offset : item.end_offset]
                (out / item.file_name).write_bytes(chunk)
                output_written += 1

        summary = {
            "media_path": str(Path(media_path).resolve()),
            "recovered_count": len(recovered),
            "written_to_output": output_written,
            "classification_enabled": True,
            "confidence_scoring_enabled": True,
            "metadata_independent_recovery": True,
        }
        self.logger.log(
            module="advanced_file_carving_recovery",
            operation="recover",
            target=summary["media_path"],
            status="success",
            details=summary,
        )
        return OperationReport(
            report_type="advanced_file_carving_recovery",
            summary=summary,
            findings=findings,
        )
