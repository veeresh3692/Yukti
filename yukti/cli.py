from __future__ import annotations

import argparse
import json

from .platform import YuktiPlatform


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="yukti",
        description="Integrated secure data erasure and advanced file recovery tool.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    drive = sub.add_parser("drive-erase", help="Securely erase files under a mounted drive path")
    drive.add_argument("mount_path")
    drive.add_argument("--passes", type=int, default=3)

    file_erase = sub.add_parser("file-erase", help="Securely erase selected files/folders")
    file_erase.add_argument("targets", nargs="+")
    file_erase.add_argument("--passes", type=int, default=3)

    recover = sub.add_parser("recover", help="Carve recoverable files from media image")
    recover.add_argument("media_path")
    recover.add_argument("--output-dir")

    report = sub.add_parser("audit-report", help="Generate forensic audit report")
    report.add_argument("--out")

    args = parser.parse_args()
    app = YuktiPlatform()

    if args.command == "drive-erase":
        result = app.secure_erase_drive(args.mount_path, passes=args.passes)
    elif args.command == "file-erase":
        result = app.secure_erase_files_folders(args.targets, passes=args.passes)
    elif args.command == "recover":
        result = app.recover_from_media(args.media_path, output_dir=args.output_dir)
    else:
        result = app.forensic_report()

    if args.command == "audit-report" and args.out:
        app.export_report(result, args.out)

    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
