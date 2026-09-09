# Performance Evaluation Report

## Benchmark Scope
- Measure elapsed time for secure drive sanitization on a sample image.
- Measure elapsed time and output count for carving-based recovery.

## Execution
```bash
PYTHONPATH=src python benchmarks/benchmark.py
```

## Reported Metrics
- `drive_sanitize_seconds`
- `recovery_seconds`
- `recovered_artifacts`

## Sample Run (Current Implementation)
- `drive_sanitize_seconds=0.0013`
- `recovery_seconds=0.0508`
- `recovered_artifacts=200`

## Interpretation
- Lower sanitization and recovery times indicate better throughput.
- Recovered artifact count helps compare carving effectiveness across datasets.
