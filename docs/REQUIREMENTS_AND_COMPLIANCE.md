# Product Scope and Compliance Baseline

## Functional Scope
- Secure Drive Eraser: policy-driven wipe, verification, tamper-evident audit trail, destruction report.
- Secure File & Folder Eraser: selective and batch secure erase, metadata trace removal, verification logs.
- Advanced Recovery: signature-based and structure-based carving from raw/formatted media, fragmented artifact handling, confidence scoring.
- Reporting Layer: centralized audit, forensic reports, sanitization certificates, integrity verification.

## Supported Platforms
- Storage: HDD, SSD, USB, memory cards, external drives.
- File systems: NTFS, FAT32, exFAT, EXT4, XFS, APFS, HFS+.
- OS: Linux, Windows, macOS.

## Standards Baseline
- Sanitization: NIST SP 800-88 (Clear/Purge), DoD 5220.22-M profiles.
- Forensics: ISO/IEC 27037 evidence handling and ACPO evidence principles.

## Measurable Acceptance Requirements
- Every erase workflow must emit verification evidence and audit records.
- Audit records must be tamper-evident through hash chaining.
- Recovery artifacts must include confidence score and cryptographic digest.
- Reports must include integrity signature and pass signature verification.
