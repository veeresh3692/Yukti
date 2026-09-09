from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ChainOfCustodyRecord:
    action: str
    actor: str
    timestamp: str = field(default_factory=utc_now)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class VerificationResult:
    success: bool
    method: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RecoveryArtifact:
    path: str
    file_type: str
    confidence: float
    method: str
    metadata: dict[str, Any] = field(default_factory=dict)
