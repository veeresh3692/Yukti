# Yukti User Manual

## Installation
```bash
pip install -e .
```

## Commands

### 1) Secure Drive Erasure
```bash
yukti --workspace ./workspace --actor analyst sanitize-drive /path/to/device.img --profile purge
```

### 2) Secure File/Folder Erasure
```bash
yukti --workspace ./workspace --actor analyst sanitize-files /path/file1 /path/folderA --profile dod
```

### 3) Advanced Recovery and Carving
```bash
yukti --workspace ./workspace --actor analyst recover /path/to/disk_image.bin --output-dir ./recovered
```

## Output
- Audit log: `workspace/audit/audit.log`
- Reports: `workspace/reports/*.json`
- Recovered files: selected `--output-dir`

## Verification
- Reports include a `tamper_evident_signature`.
- Audit log entries are hash chained for integrity checks.
