"""Run the image pipeline in the sandbox child (or in-process when the sandbox is disabled in tests)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys

from angel_engine.images.pipeline import config_to_dict, from_dict, run_pipeline
from angel_engine.images.types import PipelineConfig, PipelineResult

JOB_TIMEOUT_S = 180.0
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


class SandboxFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def analyze(
    data: bytes, declared_mime: str | None, config: PipelineConfig, *, deadline: float = JOB_TIMEOUT_S
) -> PipelineResult:
    if not config.sandbox:
        return await asyncio.to_thread(run_pipeline, data, declared_mime, config)
    header = json.dumps({"declared_mime": declared_mime, "config": config_to_dict(config)}).encode() + b"\n"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "OMP_NUM_THREADS": "1"}
    if "TESSDATA_PREFIX" in os.environ:
        env["TESSDATA_PREFIX"] = os.environ["TESSDATA_PREFIX"]
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-I", "-m", "angel_engine.images.sandbox.child",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        env=env, start_new_session=True,
    )  # fmt: skip
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(header + data), timeout=deadline)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        raise SandboxFailed("timeout") from exc
    if proc.returncode != 0 or not stdout or len(stdout) > MAX_OUTPUT_BYTES:
        raise SandboxFailed(f"exit_{proc.returncode}")
    try:
        payload = json.loads(stdout)
    except ValueError as exc:
        raise SandboxFailed("invalid_output") from exc
    if payload.get("error"):
        raise SandboxFailed(str(payload["error"])[:60])
    return from_dict(payload)
