# Yukti

Yukti is a unified baseline platform for secure data sanitization and forensic recovery.

## Implemented core modules

1. **Secure Drive Eraser**
   - Securely wipes files under a mounted drive path using multi-pass overwrite.
   - Includes verification checks and per-target audit logging.

2. **Secure File & Folder Eraser**
   - Selective secure deletion of files/folders with metadata trace reduction via scrubbed renaming before deletion.
   - Supports batch operations and erasure verification reporting.

3. **Advanced File Carving and Recovery**
   - Signature-based carving for PNG, JPG, PDF, and ZIP from raw media bytes.
   - Metadata-independent recovery, file classification, and confidence scoring.

## Audit and forensic reporting

- Tamper-evident hash-chained audit trail.
- JSON report export for erasure/recovery and forensic audit summaries.

## CLI usage

```bash
python -m yukti.cli drive-erase /path/to/mounted/drive --passes 3
python -m yukti.cli file-erase /path/to/file1 /path/to/folder2 --passes 3
python -m yukti.cli recover /path/to/media.img --output-dir /path/to/recovered
python -m yukti.cli audit-report --out /path/to/report.json
```

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
