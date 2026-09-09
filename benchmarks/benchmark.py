from __future__ import annotations

import tempfile
import time
from pathlib import Path

from yukti.orchestrator import YuktiPlatform


def run() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        platform = YuktiPlatform(base / "workspace")

        device = base / "device.img"
        device.write_bytes(b"A" * (1024 * 1024 * 4))
        start = time.perf_counter()
        platform.sanitize_drive(device, "clear", "benchmark")
        drive_time = time.perf_counter() - start

        image = base / "image.bin"
        image.write_bytes((b"PK\x03\x04" + b"\x00" * 300 + b"PK\x05\x06") * 200)
        start = time.perf_counter()
        artifacts, _ = platform.recover(image, base / "recovered", "benchmark")
        recovery_time = time.perf_counter() - start

        print(f"drive_sanitize_seconds={drive_time:.4f}")
        print(f"recovery_seconds={recovery_time:.4f}")
        print(f"recovered_artifacts={len(artifacts)}")


if __name__ == "__main__":
    run()
