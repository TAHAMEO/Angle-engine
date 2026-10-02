"""Run document extraction in an isolated, resource-limited child process (or in-process for tests)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys
from typing import Any

EXTRACT_TIMEOUT_S = 45.0
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class ExtractionFailed(Exception):
    pass


async def extract_document(
    content: bytes,
    content_type: str | None,
    url: str,
    *,
    sandbox: bool = True,
    timeout: float = EXTRACT_TIMEOUT_S,  # noqa: ASYNC109 - the subprocess deadline is the point of this API
) -> dict[str, Any]:
    if not sandbox:
        from angel_engine.osint.extract import extract

        return await asyncio.to_thread(extract, content, content_type, url)
    header = json.dumps({"content_type": content_type, "url": url}).encode() + b"\n"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "OMP_NUM_THREADS": "1"}
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-I", "-m", "angel_engine.osint.extract_child",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        env=env, start_new_session=True,
    )  # fmt: skip
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(header + content), timeout=timeout)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        raise ExtractionFailed("timeout") from exc
    if proc.returncode != 0 or not stdout or len(stdout) > MAX_OUTPUT_BYTES:
        raise ExtractionFailed(f"exit {proc.returncode}")
    try:
        result: dict[str, Any] = json.loads(stdout)
    except ValueError as exc:
        raise ExtractionFailed("invalid output") from exc
    if result.get("kind") == "error":
        raise ExtractionFailed(str(result.get("error")))
    return result
