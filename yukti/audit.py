from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from .models import AuditEntry, utc_now_iso


class AuditLogger:
    """Tamper-evident audit logger using hash chaining."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def _entry_hash(
        self,
        timestamp: str,
        module: str,
        operation: str,
        target: str,
        status: str,
        details: Dict[str, Any],
        previous_hash: str,
    ) -> str:
        payload = {
            "timestamp": timestamp,
            "module": module,
            "operation": operation,
            "target": target,
            "status": status,
            "details": details,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log(
        self,
        module: str,
        operation: str,
        target: str,
        status: str,
        details: Dict[str, Any] | None = None,
    ) -> AuditEntry:
        timestamp = utc_now_iso()
        prev = self._entries[-1].entry_hash if self._entries else "GENESIS"
        details = details or {}
        entry_hash = self._entry_hash(
            timestamp=timestamp,
            module=module,
            operation=operation,
            target=target,
            status=status,
            details=details,
            previous_hash=prev,
        )
        entry = AuditEntry(
            timestamp=timestamp,
            module=module,
            operation=operation,
            target=target,
            status=status,
            details=details,
            previous_hash=prev,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def validate_chain(self) -> bool:
        prev = "GENESIS"
        for entry in self._entries:
            expected = self._entry_hash(
                timestamp=entry.timestamp,
                module=entry.module,
                operation=entry.operation,
                target=entry.target,
                status=entry.status,
                details=entry.details,
                previous_hash=prev,
            )
            if expected != entry.entry_hash or entry.previous_hash != prev:
                return False
            prev = entry.entry_hash
        return True

    def export(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self._entries]
