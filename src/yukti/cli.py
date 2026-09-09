from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dashboard import DashboardService
from .orchestrator import YuktiPlatform


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Yukti Secure Erasure and Recovery")
    parser.add_argument("--workspace", default="./yukti_workspace", help="Workspace for logs and reports")
    parser.add_argument("--actor", default="operator", help="Operator identity for audit records")
    sub = parser.add_subparsers(dest="command", required=True)

    drive = sub.add_parser("sanitize-drive", help="Securely sanitize a drive image file")
    drive.add_argument("device_path")
    drive.add_argument("--profile", default="clear", choices=["clear", "purge", "dod"])

    files = sub.add_parser("sanitize-files", help="Securely sanitize files or folders")
    files.add_argument("paths", nargs="+")
    files.add_argument("--profile", default="clear", choices=["clear", "purge", "dod"])

    recover = sub.add_parser("recover", help="Recover carved files from forensic image")
    recover.add_argument("image_path")
    recover.add_argument("--output-dir", default="./recovered")

    sub.add_parser("dashboard", help="Show dashboard status for reports and audit integrity")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    platform = YuktiPlatform(Path(args.workspace).resolve())

    if args.command == "sanitize-drive":
        result, report = platform.sanitize_drive(Path(args.device_path), args.profile, args.actor)
        print(f"Drive sanitization success={result.success}, report={report}")
    elif args.command == "sanitize-files":
        results, report = platform.sanitize_files((Path(p) for p in args.paths), args.profile, args.actor)
        successful = sum(1 for item in results if item.success)
        print(f"File sanitization verified={successful}/{len(results)}, report={report}")
    elif args.command == "recover":
        artifacts, report = platform.recover(Path(args.image_path), Path(args.output_dir), args.actor)
        print(f"Recovered artifacts={len(artifacts)}, report={report}")
    elif args.command == "dashboard":
        dashboard = DashboardService(Path(args.workspace).resolve())
        print(json.dumps(dashboard.status(), indent=2))


if __name__ == "__main__":
    main()
