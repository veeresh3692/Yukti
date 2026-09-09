from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    module: str
    operation: str
    target: str
    status: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RecoveredFile:
    file_name: str
    extension: str
    category: str
    confidence_score: float
    start_offset: int
    end_offset: int
    sha256: str
    size: int
    metadata_based: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["confidence_score"] = round(self.confidence_score, 3)
        return data


@dataclass
class OperationReport:
    report_type: str
    generated_at: str = field(default_factory=utc_now_iso)
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    audit_trail: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "findings": self.findings,
            "audit_trail": self.audit_trail,
        }
