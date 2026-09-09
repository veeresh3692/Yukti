from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import utc_now


@dataclass(slots=True)
class AuditEntry:
    timestamp: str
    actor: str
    action: str
    context: dict[str, Any]
    previous_hash: str
    entry_hash: str


class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return "GENESIS"
        lines = [line for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1])["entry_hash"]

    def log(self, actor: str, action: str, context: dict[str, Any]) -> AuditEntry:
        previous_hash = self._last_hash()
        payload = {"timestamp": utc_now(), "actor": actor, "action": action, "context": context, "previous_hash": previous_hash}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        entry = AuditEntry(entry_hash=digest, **payload)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
        return entry

    def verify_chain(self) -> bool:
        if not self.log_path.exists():
            return True
        previous = "GENESIS"
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry["previous_hash"] != previous:
                return False
            payload = {
                "timestamp": entry["timestamp"],
                "actor": entry["actor"],
                "action": entry["action"],
                "context": entry["context"],
                "previous_hash": entry["previous_hash"],
            }
            expected = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            if expected != entry["entry_hash"]:
                return False
            previous = entry["entry_hash"]
        return True
