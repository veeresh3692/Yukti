from __future__ import annotations

import json
from pathlib import Path

from .audit import AuditLogger


class DashboardService:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.reports_dir = workspace / "reports"
        self.audit_path = workspace / "audit" / "audit.log"

    def status(self) -> dict:
        reports = []
        if self.reports_dir.exists():
            for report in sorted(self.reports_dir.glob("*.json")):
                data = json.loads(report.read_text(encoding="utf-8"))
                reports.append(
                    {
                        "name": report.name,
                        "signature": data.get("tamper_evident_signature"),
                        "actor": data.get("payload", {}).get("actor"),
                    }
                )
        audit_ok = AuditLogger(self.audit_path).verify_chain()
        return {"report_count": len(reports), "reports": reports, "audit_chain_valid": audit_ok}
