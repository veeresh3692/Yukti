# Technical Documentation

## Implementation Notes
- Language: Python 3.10+
- Packaging: `pyproject.toml` with console entrypoint `yukti`.
- Core package: `src/yukti`.

## Module Map
- `compliance.py`: supported platforms, standards, measurable requirements.
- `erasure_profiles.py`: policy profiles for clear/purge/dod.
- `audit.py`: tamper-evident hash-chained audit logger.
- `drive_eraser.py`: profile-based secure drive overwrite and verification.
- `file_eraser.py`: secure file/folder overwrite-delete with batch support.
- `recovery.py`: acquisition, signature-based carving, classification, confidence scoring.
- `reporting.py`: signed JSON reporting and report integrity verification.
- `orchestrator.py`: integrated workflow orchestration.
- `cli.py`: operator interface for sanitize/recover operations.

## Security and Integrity Controls
- Hash chaining for immutable-sequence audit behavior.
- SHA-256 digest for recovered artifacts and case reports.
- Explicit actor attribution on all critical operations.
