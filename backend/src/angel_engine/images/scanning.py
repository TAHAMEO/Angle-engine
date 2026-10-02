"""Malware scanning of uploads before anything else touches them.

* :class:`ClamdScanner` streams the bytes to clamd with ``zINSTREAM``. It **fails closed**: if clamd is
  unreachable or times out, :class:`ScannerUnavailable` is raised and the scan job retries later; the
  image never becomes ``clean`` without a verdict. ``Heuristics.*`` detections (broken media, exceeded
  limits — clamd must run with ``AlertBrokenMedia`` and ``AlertExceedsMax`` enabled) are rejections too.
* :class:`BuiltinScanner` is a development-only stand-in (EICAR test string plus a few structural checks
  for embedded executables and scripts). It reports ``degraded=True`` so the UI shows a "scanning degraded"
  banner, and :func:`build_scanner` refuses it in production.

Only the signature name (sanitized) is kept; scanner output never includes file content.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from angel_engine.config import Settings

CHUNK = 64 * 1024
REPLY_LIMIT = 4096
_SIGNATURE = re.compile(r"[A-Za-z0-9._:/+-]{1,120}")


class ScanVerdict(StrEnum):
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"  # the scanner answered but could not scan (e.g. size limit): treated as a failure


@dataclass(frozen=True, slots=True)
class ScanResult:
    verdict: ScanVerdict
    engine: str
    signature: str | None = None
    degraded: bool = False

    @property
    def heuristic(self) -> bool:
        return bool(self.signature and self.signature.startswith("Heuristics."))


class ScannerUnavailable(Exception):
    """The scanner could not be reached; the job must retry (never treat the file as clean)."""


class MalwareScanner(Protocol):
    name: str
    degraded: bool

    async def scan(self, data: bytes) -> ScanResult: ...

    async def ping(self) -> bool: ...


def _clean_signature(value: str) -> str:
    value = value.strip()
    return value if _SIGNATURE.fullmatch(value) else "unknown"


def parse_reply(reply: bytes, engine: str = "clamd") -> ScanResult:
    """Parse a clamd reply such as ``stream: OK``, ``stream: Eicar-Signature FOUND`` or ``… ERROR``."""
    text = reply.rstrip(b"\0\n").decode("ascii", "replace").strip()
    body = text.split(": ", 1)[1] if text.startswith("stream: ") else text
    if body == "OK":
        return ScanResult(ScanVerdict.CLEAN, engine)
    if body.endswith(" FOUND"):
        return ScanResult(ScanVerdict.INFECTED, engine, signature=_clean_signature(body.removesuffix(" FOUND")))
    return ScanResult(ScanVerdict.ERROR, engine, signature=None)


class ClamdScanner:
    name = "clamd"
    degraded = False

    def __init__(self, *, host: str = "127.0.0.1", port: int = 3310, socket_path: str | None = None,
                 timeout: float = 120.0) -> None:  # fmt: skip
        self.host, self.port, self.socket_path, self.timeout = host, port, socket_path, timeout

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self.socket_path:
            return await asyncio.open_unix_connection(self.socket_path, limit=REPLY_LIMIT)
        return await asyncio.open_connection(self.host, self.port, limit=REPLY_LIMIT)

    async def _command(self, command: bytes, payload: bytes | None = None) -> bytes:
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await self._open()
                try:
                    try:
                        writer.write(b"z" + command + b"\0")
                        if payload is not None:
                            view = memoryview(payload)
                            for offset in range(0, len(view), CHUNK):
                                chunk = view[offset : offset + CHUNK]
                                writer.write(struct.pack(">I", len(chunk)))
                                writer.write(chunk)
                                await writer.drain()
                            writer.write(struct.pack(">I", 0))
                        await writer.drain()
                    except ConnectionError:
                        # clamd closes the stream early when a limit is hit; its reply explains why.
                        pass
                    return await reader.readuntil(b"\0")
                finally:
                    writer.close()
                    with contextlib.suppress(OSError, ConnectionError):
                        await writer.wait_closed()
        except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise ScannerUnavailable(type(exc).__name__) from exc

    async def scan(self, data: bytes) -> ScanResult:
        return parse_reply(await self._command(b"INSTREAM", data), self.name)

    async def ping(self) -> bool:
        try:
            return (await self._command(b"PING")).rstrip(b"\0") == b"PONG"
        except ScannerUnavailable:
            return False


# The EICAR anti-malware test string, assembled at import so this source file is not itself a test file.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_STRUCTURAL = (
    (re.compile(rb"\x7fELF[\x01\x02][\x01\x02]\x01"), "Builtin.Structural.EmbeddedELF"),
    (re.compile(rb"<\?php", re.IGNORECASE), "Builtin.Structural.EmbeddedPHP"),
    (re.compile(rb"<script[\s>]", re.IGNORECASE), "Builtin.Structural.EmbeddedScript"),
)


def _embedded_pe(data: bytes) -> bool:
    """An ``MZ`` header whose ``e_lfanew`` points at a ``PE\\0\\0`` signature (a Windows executable)."""
    start = data.find(b"MZ")
    while start != -1:
        if start + 0x40 <= len(data):
            (lfanew,) = struct.unpack_from("<I", data, start + 0x3C)
            if 0x40 <= lfanew <= 0x1000 and data[start + lfanew : start + lfanew + 4] == b"PE\0\0":
                return True
        start = data.find(b"MZ", start + 2)
    return False


class BuiltinScanner:
    """Development-only scanner (``ANGEL_SCANNER=builtin``); refused in production."""

    name = "builtin"
    degraded = True

    async def scan(self, data: bytes) -> ScanResult:
        if EICAR in data:
            return ScanResult(ScanVerdict.INFECTED, self.name, signature="Eicar-Test-Signature", degraded=True)
        if _embedded_pe(data):
            return ScanResult(ScanVerdict.INFECTED, self.name, signature="Builtin.Structural.EmbeddedPE",
                              degraded=True)  # fmt: skip
        for pattern, signature in _STRUCTURAL:
            if pattern.search(data):
                return ScanResult(ScanVerdict.INFECTED, self.name, signature=signature, degraded=True)
        return ScanResult(ScanVerdict.CLEAN, self.name, degraded=True)

    async def ping(self) -> bool:
        return True


def build_scanner(settings: Settings) -> MalwareScanner:
    if settings.scanner == "builtin":
        if settings.env == "production":
            raise RuntimeError("the builtin scanner is not allowed in production")
        return BuiltinScanner()
    return ClamdScanner(host=settings.clamd_host, port=settings.clamd_port, socket_path=settings.clamd_socket)


__all__ = [
    "EICAR",
    "BuiltinScanner",
    "ClamdScanner",
    "MalwareScanner",
    "ScanResult",
    "ScanVerdict",
    "ScannerUnavailable",
    "build_scanner",
    "parse_reply",
]
