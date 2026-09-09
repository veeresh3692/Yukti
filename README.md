# Yukti

Integrated secure data erasure and advanced forensic recovery platform.

## Key Modules
- Secure Drive Eraser (profile-based sanitization with verification)
- Secure File & Folder Eraser (selective and batch secure deletion)
- Advanced File Carving & Recovery (signature/structure-driven recovery)
- Reporting & Audit Management (tamper-evident logs and signed reports)

## Quick Start
```bash
pip install -e .
yukti --workspace ./workspace --actor analyst sanitize-drive /path/to/device.img --profile clear
yukti --workspace ./workspace --actor analyst sanitize-files /path/to/file /path/to/folder --profile purge
yukti --workspace ./workspace --actor analyst recover /path/to/raw_image.bin --output-dir ./recovered
```

## Repository Layout
- `/src/yukti`: core implementation
- `/tests`: validation tests
- `/docs`: scope, architecture, user and technical documentation
- `/benchmarks`: benchmark harness
