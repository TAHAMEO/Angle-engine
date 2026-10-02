"""Image sandbox child: ``python -I -m angel_engine.images.sandbox.child``.

Protocol: one JSON header line ``{"declared_mime": ..., "config": {...}}`` followed by the raw upload on
stdin; one JSON object (the serialized PipelineResult) on stdout. Resource limits are applied before Pillow,
OpenCV or any other decoder is imported, and every library runs single-threaded.
"""

from __future__ import annotations

import json
import os
import resource
import sys

LIMITS = {
    resource.RLIMIT_AS: 3 * 1024 * 1024 * 1024,
    resource.RLIMIT_CPU: 170,
    resource.RLIMIT_FSIZE: 64 * 1024 * 1024,
    resource.RLIMIT_NOFILE: 128,
    resource.RLIMIT_CORE: 0,
}


def _apply_limits() -> None:
    for kind, value in LIMITS.items():
        _soft, hard = resource.getrlimit(kind)
        cap = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(kind, (cap, cap))
    for var in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_THREAD_LIMIT"):
        os.environ[var] = "1"


def main() -> int:
    _apply_limits()
    raw = sys.stdin.buffer.read()
    header, _, body = raw.partition(b"\n")
    try:
        meta = json.loads(header)
        import cv2

        cv2.setNumThreads(1)
        from angel_engine.images.pipeline import config_from_dict, run_pipeline, to_dict

        result = to_dict(run_pipeline(body, meta.get("declared_mime"), config_from_dict(meta["config"])))
    except MemoryError:
        result = {"status": "failed", "stages": [], "error": "memory_limit"}
    except Exception as exc:  # never echo content
        result = {"status": "failed", "stages": [], "error": type(exc).__name__}
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
