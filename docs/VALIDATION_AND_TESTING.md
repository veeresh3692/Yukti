# Validation and Testing Documentation

## Test Coverage Focus
- Drive sanitization verification and signed reporting.
- Batch file/folder secure deletion workflows.
- Forensic recovery carving and classification pipeline.
- Audit chain integrity and tamper detection.
- Report signature integrity validation.

## How to Run
```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Expected Outcomes
- All tests pass.
- Audit chain remains valid for untampered logs.
- Any tampering in audit logs or reports is detected.
