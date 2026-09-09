# Unified Platform Architecture

## Core Components
1. **Device Access Layer**
   - Safe input handling for drive image/file targets.
   - Read-only acquisition path for forensic recovery.
2. **Erasure Engine**
   - Profile-based overwrite routines for drive and file workflows.
   - Per-pass logging and verification output.
3. **Metadata Cleansing Service**
   - Secure deletion flow removes target files/folders after overwrite.
   - Captures residual-cleansing event records in audit trail.
4. **Recovery/Carving Engine**
   - Signature and structure-aware scanning.
   - Fragment handling with confidence scoring.
5. **Audit/Reporting Service**
   - Hash-chained audit log.
   - Tamper-evident JSON report generator and verifier.
6. **UI/API Layer**
   - CLI workflow entry points for sanitize drive, sanitize files/folders, and recover.

## Shared Evidence-Safe Data Model
- `VerificationResult`: success flag, method, evidence payload.
- `RecoveryArtifact`: path, type, confidence, method, metadata digest.
- `ChainOfCustodyRecord`: actor, timestamp, acquisition action, checksum details.

## Workflow Orchestration
- **Sanitize Drive**: profile selection → overwrite passes → verification → signed report.
- **Sanitize Files/Folders**: target selection → batch overwrite/delete → verification → signed report.
- **Recover**: read-only acquisition → carve → classify → signed forensic report.
