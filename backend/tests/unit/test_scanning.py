"""Malware scanning: the clamd INSTREAM adapter against a mock clamd server, fail-closed behaviour, and the
development-only builtin scanner."""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from angel_engine.config import Settings
from angel_engine.images.scanning import (
    EICAR,
    BuiltinScanner,
    ClamdScanner,
    ScannerUnavailable,
    ScanVerdict,
    build_scanner,
    parse_reply,
)
from tests import imagegen

STREAM_LIMIT = 256 * 1024


async def _mock_clamd(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Implements PING and zINSTREAM like clamd 1.5 (StreamMaxLength = 256 KiB in this mock)."""
    try:
        command = await reader.readuntil(b"\0")
        if command == b"zPING\0":
            writer.write(b"PONG\0")
        elif command == b"zINSTREAM\0":
            received = bytearray()
            while True:
                (size,) = struct.unpack(">I", await reader.readexactly(4))
                if size == 0:
                    break
                received += await reader.readexactly(size)
                if len(received) > STREAM_LIMIT:
                    writer.write(b"INSTREAM size limit exceeded. ERROR\0")
                    break
            else:  # pragma: no cover - loop always breaks
                pass
            if len(received) <= STREAM_LIMIT:
                if EICAR in received:
                    writer.write(b"stream: Eicar-Test-Signature FOUND\0")
                elif received.startswith(b"BROKEN"):
                    writer.write(b"stream: Heuristics.Broken.Media.JPEG.EOFReadingHeader FOUND\0")
                else:
                    writer.write(b"stream: OK\0")
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


@pytest.fixture
async def clamd() -> AsyncIterator[ClamdScanner]:
    server = await asyncio.start_server(_mock_clamd, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield ClamdScanner(host="127.0.0.1", port=port, timeout=5)


async def test_clamd_clean_infected_heuristic_and_error(clamd: ClamdScanner) -> None:
    image = imagegen.jpeg(imagegen.pattern())
    clean = await clamd.scan(image)
    assert clean.verdict == ScanVerdict.CLEAN and clean.engine == "clamd" and not clean.degraded
    infected = await clamd.scan(image + EICAR)
    assert infected.verdict == ScanVerdict.INFECTED and infected.signature == "Eicar-Test-Signature"
    broken = await clamd.scan(b"BROKEN" + image)
    assert broken.verdict == ScanVerdict.INFECTED and broken.heuristic  # Heuristics.* are rejections too
    too_big = await clamd.scan(b"\x00" * (STREAM_LIMIT + 70_000))
    assert too_big.verdict == ScanVerdict.ERROR  # never "clean" without a verdict
    assert await clamd.ping() is True


async def test_clamd_unreachable_fails_closed() -> None:
    server = await asyncio.start_server(_mock_clamd, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    scanner = ClamdScanner(host="127.0.0.1", port=port, timeout=2)
    with pytest.raises(ScannerUnavailable):
        await scanner.scan(b"data")
    assert await scanner.ping() is False


async def test_clamd_timeout_fails_closed() -> None:
    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(5)
        writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    async with server:
        scanner = ClamdScanner(host="127.0.0.1", port=server.sockets[0].getsockname()[1], timeout=0.3)
        with pytest.raises(ScannerUnavailable):
            await scanner.scan(b"data")


def test_reply_parsing_sanitizes_signatures() -> None:
    assert parse_reply(b"stream: OK\0").verdict == ScanVerdict.CLEAN
    assert parse_reply(b"stream: Win.Test.EICAR_HDB-1 FOUND\0").signature == "Win.Test.EICAR_HDB-1"
    weird = parse_reply(b"stream: <script>alert(1)</script> FOUND\0")
    assert weird.verdict == ScanVerdict.INFECTED and weird.signature == "unknown"
    assert parse_reply(b"Can't allocate memory ERROR\0").verdict == ScanVerdict.ERROR
    assert parse_reply(b"garbage").verdict == ScanVerdict.ERROR


async def test_builtin_scanner() -> None:
    scanner = BuiltinScanner()
    image = imagegen.jpeg(imagegen.pattern())
    assert (await scanner.scan(image)).verdict == ScanVerdict.CLEAN
    result = await scanner.scan(image + EICAR)
    assert result.verdict == ScanVerdict.INFECTED and result.degraded
    pe = bytearray(b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x80) + b"\0" * 0x40 + b"PE\0\0" + b"\0" * 32)
    assert (await scanner.scan(image + bytes(pe))).signature == "Builtin.Structural.EmbeddedPE"
    assert (await scanner.scan(image + b"<?php echo 1; ?>")).signature == "Builtin.Structural.EmbeddedPHP"


def test_builtin_scanner_refused_in_production() -> None:
    assert isinstance(build_scanner(Settings(env="test", scanner="builtin")), BuiltinScanner)
    assert isinstance(build_scanner(Settings(env="test", scanner="clamd")), ClamdScanner)
    with pytest.raises(ValueError, match="ANGEL_SCANNER"):
        Settings(env="production", scanner="builtin")
