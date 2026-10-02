"""Sandbox child: ``python -I -m angel_engine.osint.extract_child``.

Reads one JSON header line (``{"content_type": ..., "url": ...}``) followed by the raw document bytes on
stdin and writes the extraction result as one JSON object on stdout. Resource limits are applied *before*
any parser is imported.
"""

from __future__ import annotations

import json
import os
import resource
import sys

LIMITS = {
    resource.RLIMIT_AS: 1024 * 1024 * 1024,  # 1 GiB address space
    resource.RLIMIT_CPU: 30,  # seconds
    resource.RLIMIT_FSIZE: 1024 * 1024,  # no meaningful file writes
    resource.RLIMIT_NOFILE: 64,
    resource.RLIMIT_CORE: 0,
}


def _apply_limits() -> None:
    for kind, value in LIMITS.items():
        _soft, hard = resource.getrlimit(kind)
        cap = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(kind, (cap, cap))


def main() -> int:
    _apply_limits()
    os.environ["OMP_NUM_THREADS"] = "1"
    raw = sys.stdin.buffer.read()
    header, _, body = raw.partition(b"\n")
    try:
        meta = json.loads(header)
        from angel_engine.osint.extract import extract

        result = extract(body, meta.get("content_type"), str(meta.get("url", "")))
    except MemoryError:
        result = {"kind": "error", "error": "memory_limit"}
    except Exception as exc:  # report, never crash with a traceback containing document content
        result = {"kind": "error", "error": type(exc).__name__}
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
