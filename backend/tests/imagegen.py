"""Synthetic test images generated at test time (no real photographs and no real faces anywhere)."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from PIL import Image, ImageDraw, ImageFont

MAGENTA = (255, 0, 255)  # the fixture face detector reports this marker colour as a "face"


def _jpeg(img: Image.Image, exif: Image.Exif | None = None, quality: int = 92) -> bytes:
    buf = io.BytesIO()
    if exif is not None:
        img.save(buf, format="JPEG", quality=quality, exif=exif)
    else:
        img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def storefront(*, with_exif: bool = True, marker: bool = False, size: tuple[int, int] = (1600, 1000)) -> bytes:
    """A fictional shop sign with visible text and (optionally) camera EXIF incl. GPS in Lisbon."""
    img = Image.new("RGB", size, (40, 60, 80))
    d = ImageDraw.Draw(img)
    big = ImageFont.load_default(size=72)
    mid = ImageFont.load_default(size=48)
    d.rectangle([80, 80, 1520, 420], fill=(245, 240, 230))
    d.text((120, 110), "NORTHWIND COFFEE ROASTERS", font=big, fill=(20, 20, 20))
    d.text((120, 220), "EST. 2016", font=mid, fill=(20, 20, 20))
    d.text((120, 300), "northwind-coffee.example", font=mid, fill=(20, 20, 20))
    d.rectangle([80, 500, 1520, 900], fill=(250, 250, 250))
    d.text((120, 540), "@northwindroasters", font=mid, fill=(10, 10, 10))
    d.text((120, 640), "OPEN DAILY 7-18", font=mid, fill=(10, 10, 10))
    d.text((120, 740), "HARBOUR STREET  LISBON", font=mid, fill=(10, 10, 10))
    if marker:  # a magenta "face" stand-in with fine detail inside
        d.rectangle([1300, 560, 1460, 760], fill=MAGENTA)
        d.text((1312, 620), "ID 4471", font=ImageFont.load_default(size=36), fill=(0, 0, 0))
        d.text((1312, 680), "X9 Q2", font=ImageFont.load_default(size=36), fill=(0, 0, 0))
    if not with_exif:
        return _jpeg(img)
    exif = Image.Exif()
    exif[271] = "DemoCam"
    exif[272] = "DC-100"
    exif[305] = "Adobe Photoshop 26.0"
    exif[306] = "2026:06:20 18:00:00"
    exif[315] = "Jane Example"  # artist: identifying, must become a fingerprint
    ex = exif.get_ifd(0x8769)
    ex[36867] = "2026:06:14 09:12:33"
    ex[36881] = "+01:00"
    ex[42033] = "DC100-0004471"  # body serial number: identifying
    ex[33437] = 2.8
    gps = exif.get_ifd(0x8825)
    gps[1], gps[2] = "N", (38.0, 43.0, 20.28)
    gps[3], gps[4] = "W", (9.0, 8.0, 21.48)
    return _jpeg(img, exif)


def pattern(seed: int = 1, size: tuple[int, int] = (640, 480)) -> Image.Image:
    """A deterministic geometric pattern with enough structure for perceptual hashes."""
    img = Image.new("RGB", size, (230, 230, 225))
    d = ImageDraw.Draw(img)
    w, h = size
    for i in range(12):
        x = (seed * 97 + i * 53) % (w - 80)
        y = (seed * 31 + i * 71) % (h - 80)
        colour = ((seed * 40 + i * 20) % 256, (i * 35) % 256, (seed * 15 + i * 50) % 256)
        d.rectangle([x, y, x + 60 + i * 3, y + 40 + i * 2], fill=colour)
    d.ellipse([w // 3, h // 3, w // 3 + 120, h // 3 + 90], fill=(20, 40, 160))
    return img


def jpeg(img: Image.Image, quality: int = 90) -> bytes:
    return _jpeg(img, quality=quality)


def png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def with_zip_appended(data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    return data + buf.getvalue()


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png_bomb(width: int = 60_000, height: int = 60_000) -> bytes:
    """A tiny, valid PNG whose header declares enormous dimensions."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00" * 64)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
