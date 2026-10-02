"""Upload validation without decoding.

Pure Python: magic-byte sniffing, agreement with the declared MIME type, a structural walk of the
container (JPEG markers, PNG chunks with CRC, GIF blocks, RIFF chunks, TIFF IFDs, BMP header,
ISO-BMFF boxes) to find the dimensions and the *logical end* of the image, and a signature sniff of
any data appended after it (polyglot detection). No image decoder runs here, so the API process can
call :func:`validate_upload` synchronously on untrusted bytes before queueing the analysis job.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib
from dataclasses import dataclass

from angel_engine.images.errors import ImageRejected
from angel_engine.images.types import FileInfo, PipelineConfig

ID = "file_info"
VERSION = "1"

FORMAT_MIME = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "WEBP": "image/webp",
    "TIFF": "image/tiff",
    "BMP": "image/bmp",
    "HEIF": "image/heic",
}
_MIME_ALIASES = {
    "image/jpg": "image/jpeg",
    "image/pjpeg": "image/jpeg",
    "image/x-png": "image/png",
    "image/apng": "image/png",
    "image/vnd.mozilla.apng": "image/png",
    "image/x-ms-bmp": "image/bmp",
    "image/x-bmp": "image/bmp",
    "image/tif": "image/tiff",
    "image/x-tiff": "image/tiff",
    "image/heif": "image/heic",
    "image/heic-sequence": "image/heic",
    "image/heif-sequence": "image/heic",
}
_UNDECLARED = frozenset({"", "application/octet-stream", "binary/octet-stream"})
_HEIF_BRANDS = frozenset({b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1", b"msf1"})
_AVIF_BRANDS = frozenset({b"avif", b"avis"})

#: Trailing-data signatures that put the upload in quarantine (archives, executables, scripts, HTML).
QUARANTINE_SIGNATURES = frozenset({"zip", "rar", "7z", "pdf", "pe", "elf", "php", "html", "script"})

_SOF_MARKERS = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
_SCAN_MARKER = re.compile(rb"\xff+[^\x00\xd0-\xd7\xff]")
_HTML = re.compile(rb"(?i)<(?:!doctype\s+html|html[\s>]|head[\s>]|body[\s>]|script[\s>/]|iframe[\s>/]|svg[\s>/])")
_PHP = re.compile(rb"(?i)<\?php")
_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}
_TIFF_SUB_IFD_TAGS = frozenset({330, 34665, 34853, 40965})
_TIFF_ARRAY_TAGS = frozenset({256, 257, 258, 262, 273, 277, 279, 324, 325, 330, 338, 513, 514, 34665, 34853, 40965})
_MAX_TIFF_IFDS = 64
_MAX_TIFF_ENTRIES = 8192
_MAX_TIFF_ARRAY = 262_144


@dataclass(slots=True)
class _Structure:
    width: int
    height: int
    end: int
    frames: int = 1
    mode: str = "RGB"
    has_alpha: bool = False
    has_icc: bool = False


def _truncated() -> ImageRejected:
    return ImageRejected("truncated", "The image file is truncated.")


def _corrupt() -> ImageRejected:
    return ImageRejected("corrupt", "The image file is damaged or malformed.")


# --------------------------------------------------------------------------------------------- sniff


def sniff_format(data: bytes, *, allow_heif: bool = False) -> str:
    """Return the Pillow format name for ``data`` or raise :class:`ImageRejected`."""
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    if data[:4] in (b"II+\x00", b"MM\x00+"):
        raise ImageRejected("bigtiff_not_supported", "BigTIFF files are not supported.")
    if data[:2] == b"BM" and len(data) >= 26:
        return "BMP"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brands = _ftyp_brands(data)
        if brands & _AVIF_BRANDS:
            raise ImageRejected("avif_not_supported", "AVIF images are not supported.")
        if brands & _HEIF_BRANDS:
            if not allow_heif or not _heif_available():
                raise ImageRejected("heif_disabled", "HEIC/HEIF images are not enabled on this server.")
            return "HEIF"
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<svg", b"<?xml", b"<!doctype svg")) or b"<svg" in head:
        raise ImageRejected("svg_not_allowed", "SVG images are not accepted.")
    raise ImageRejected("unsupported_format", "The file is not a supported image format.")


def _ftyp_brands(data: bytes) -> set[bytes]:
    size = int.from_bytes(data[0:4], "big")
    if size < 16 or size > min(len(data), 4096):
        size = min(len(data), 64)
    brands = {data[8:12]}
    brands.update(data[i : i + 4] for i in range(16, size - 3, 4))
    return brands


def _heif_available() -> bool:
    try:
        import pillow_heif  # noqa: F401
    except ImportError:
        return False
    return True


def normalize_mime(declared: str | None) -> str | None:
    """Lower-case, strip parameters and map aliases; ``None`` for absent/generic declarations."""
    if declared is None:
        return None
    base = declared.split(";", 1)[0].strip().lower()
    if base in _UNDECLARED:
        return None
    return _MIME_ALIASES.get(base, base)


# ----------------------------------------------------------------------------------------- walkers


def _walk_jpeg(d: bytes) -> _Structure:
    n = len(d)
    pos = 2
    width = height = components = 0
    icc = False
    scans = 0
    while True:
        if pos >= n:
            raise _truncated()
        if d[pos] != 0xFF:
            raise _corrupt()
        while pos < n and d[pos] == 0xFF:
            pos += 1
        if pos >= n:
            raise _truncated()
        marker = d[pos]
        pos += 1
        if marker == 0xD9:
            if not scans or not width:
                raise _corrupt()
            mode = {1: "L", 3: "RGB", 4: "CMYK"}.get(components, "RGB")
            return _Structure(width, height, pos, mode=mode, has_icc=icc)
        if marker in (0x00, 0xD8):
            raise _corrupt()
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if pos + 2 > n:
            raise _truncated()
        seg_len = int.from_bytes(d[pos : pos + 2], "big")
        if seg_len < 2:
            raise _corrupt()
        seg_end = pos + seg_len
        if seg_end > n:
            raise _truncated()
        if marker in _SOF_MARKERS:
            if seg_len < 8:
                raise _corrupt()
            height = int.from_bytes(d[pos + 3 : pos + 5], "big")
            width = int.from_bytes(d[pos + 5 : pos + 7], "big")
            components = d[pos + 7]
        elif marker == 0xE2 and d[pos + 2 : pos + 14] == b"ICC_PROFILE\x00":
            icc = True
        pos = seg_end
        if marker == 0xDA:
            scans += 1
            match = _SCAN_MARKER.search(d, pos)
            if match is None:
                raise _truncated()
            pos = match.start()


def _walk_png(d: bytes) -> _Structure:
    n = len(d)
    pos = 8
    first = True
    info: _Structure | None = None
    has_idat = False
    while True:
        if pos + 12 > n:
            raise _truncated()
        length = int.from_bytes(d[pos : pos + 4], "big")
        ctype = d[pos + 4 : pos + 8]
        if length > 0x7FFFFFFF or not ctype.isalpha():
            raise _corrupt()
        end = pos + 12 + length
        if end > n:
            raise _truncated()
        if zlib.crc32(d[pos + 4 : end - 4]) != int.from_bytes(d[end - 4 : end], "big"):
            raise _corrupt()
        body = d[pos + 8 : end - 4]
        if first:
            if ctype != b"IHDR" or length != 13:
                raise _corrupt()
            width, height = struct.unpack(">II", body[:8])
            bit_depth, color_type = body[8], body[9]
            mode = {0: "L", 2: "RGB", 3: "P", 4: "LA", 6: "RGBA"}.get(color_type)
            if mode is None:
                raise _corrupt()
            if mode == "L" and bit_depth == 16:
                mode = "I;16"
            elif mode == "L" and bit_depth == 1:
                mode = "1"
            info = _Structure(width, height, 0, mode=mode, has_alpha=color_type in (4, 6))
            first = False
        elif info is not None:
            if ctype == b"IDAT":
                has_idat = True
            elif ctype == b"tRNS":
                info.has_alpha = True
            elif ctype == b"iCCP":
                info.has_icc = True
            elif ctype == b"acTL" and length >= 8:
                info.frames = max(1, int.from_bytes(body[:4], "big"))
            elif ctype == b"IEND":
                if not has_idat:
                    raise _corrupt()
                info.end = end
                return info
        pos = end


def _skip_gif_sub_blocks(d: bytes, pos: int) -> int:
    n = len(d)
    while True:
        if pos >= n:
            raise _truncated()
        size = d[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size


def _walk_gif(d: bytes) -> _Structure:
    n = len(d)
    if n < 13:
        raise _truncated()
    width, height = struct.unpack("<HH", d[6:10])
    packed = d[10]
    pos = 13
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 7) + 1))
    frames = 0
    alpha = False
    while True:
        if pos >= n:
            raise _truncated()
        block = d[pos]
        if block == 0x3B:
            if frames == 0:
                raise _corrupt()
            return _Structure(width, height, pos + 1, frames=frames, mode="P", has_alpha=alpha)
        if block == 0x21:
            if pos + 2 > n:
                raise _truncated()
            if d[pos + 1] == 0xF9 and pos + 4 <= n and d[pos + 3] & 0x01:
                alpha = True
            pos = _skip_gif_sub_blocks(d, pos + 2)
        elif block == 0x2C:
            if pos + 10 > n:
                raise _truncated()
            local = d[pos + 9]
            pos += 10
            if local & 0x80:
                pos += 3 * (2 ** ((local & 7) + 1))
            pos = _skip_gif_sub_blocks(d, pos + 1)
            frames += 1
        else:
            raise _corrupt()


def _walk_webp(d: bytes) -> _Structure:
    n = len(d)
    riff_size = int.from_bytes(d[4:8], "little")
    end = 8 + riff_size
    if riff_size < 4:
        raise _corrupt()
    if end > n:
        raise _truncated()
    pos = 12
    width = height = 0
    frames = 0
    alpha = icc = False
    canvas = False
    while pos + 8 <= end:
        fourcc = d[pos : pos + 4]
        size = int.from_bytes(d[pos + 4 : pos + 8], "little")
        body = d[pos + 8 : pos + 8 + size]
        if pos + 8 + size > end:
            raise _corrupt()
        if fourcc == b"VP8X" and size >= 10:
            flags = body[0]
            icc, alpha = bool(flags & 0x20), bool(flags & 0x10)
            width = int.from_bytes(body[4:7], "little") + 1
            height = int.from_bytes(body[7:10], "little") + 1
            canvas = True
        elif fourcc == b"VP8 " and size >= 10 and not canvas:
            if body[3:6] != b"\x9d\x01\x2a":
                raise _corrupt()
            width = int.from_bytes(body[6:8], "little") & 0x3FFF
            height = int.from_bytes(body[8:10], "little") & 0x3FFF
        elif fourcc == b"VP8L" and size >= 5 and not canvas:
            if body[0] != 0x2F:
                raise _corrupt()
            bits = int.from_bytes(body[1:5], "little")
            width = (bits & 0x3FFF) + 1
            height = ((bits >> 14) & 0x3FFF) + 1
            alpha = bool((bits >> 28) & 1)
        elif fourcc == b"ANMF":
            frames += 1
        elif fourcc == b"ALPH":
            alpha = True
        pos += 8 + size + (size & 1)
    if not width or not height:
        raise _corrupt()
    return _Structure(
        width, height, end, frames=max(frames, 1), mode="RGBA" if alpha else "RGB", has_alpha=alpha, has_icc=icc
    )


def _walk_tiff(d: bytes) -> _Structure:
    n = len(d)
    e = "<" if d[:2] == b"II" else ">"
    first_ifd = struct.unpack_from(e + "I", d, 4)[0]
    max_end = 8
    visited: set[int] = set()
    pending: list[tuple[int, bool]] = [(first_ifd, True)]
    pages = 0
    entries_seen = 0
    width = height = 0
    samples = 1
    photometric = 2
    bits = 8
    alpha = icc = False
    page0 = True
    while pending:
        offset, main_chain = pending.pop(0)
        if offset == 0:
            continue
        if offset in visited or len(visited) >= _MAX_TIFF_IFDS or offset + 2 > n:
            raise _corrupt()
        visited.add(offset)
        count = struct.unpack_from(e + "H", d, offset)[0]
        entries_seen += count
        table_end = offset + 2 + 12 * count + 4
        if entries_seen > _MAX_TIFF_ENTRIES or table_end > n:
            raise _corrupt()
        max_end = max(max_end, table_end)
        values: dict[int, list[int]] = {}
        for i in range(count):
            tag, typ, cnt = struct.unpack_from(e + "HHI", d, offset + 2 + 12 * i)
            size = _TIFF_TYPE_SIZES.get(typ, 1) * cnt
            value_pos = offset + 2 + 12 * i + 8
            if size > 4:
                value_pos = struct.unpack_from(e + "I", d, value_pos)[0]
                if value_pos + size > n:
                    raise _truncated()
                max_end = max(max_end, value_pos + size)
            if typ in (3, 4, 13) and tag in _TIFF_ARRAY_TAGS:
                if cnt > _MAX_TIFF_ARRAY:
                    raise _corrupt()
                fmt = {3: "H", 4: "I", 13: "I"}[typ]
                values[tag] = list(struct.unpack_from(f"{e}{cnt}{fmt}", d, value_pos))
            elif tag == 34675:
                icc = True
        for off_tag, len_tag in ((273, 279), (324, 325), (513, 514)):
            offs, lens = values.get(off_tag, []), values.get(len_tag, [])
            for off, length in zip(offs, lens, strict=False):
                if off + length > n:
                    raise _truncated()
                max_end = max(max_end, off + length)
        for tag in _TIFF_SUB_IFD_TAGS:
            pending.extend((sub, False) for sub in values.get(tag, []))
        if main_chain:
            pages += 1
            if page0:
                width = values.get(256, [0])[0]
                height = values.get(257, [0])[0]
                samples = values.get(277, [1])[0]
                photometric = values.get(262, [2])[0]
                bits = values.get(258, [8])[0]
                alpha = bool(set(values.get(338, [])) & {1, 2}) or (photometric == 2 and samples >= 4)
                page0 = False
            pending.append((struct.unpack_from(e + "I", d, offset + 2 + 12 * count)[0], True))
    if not width or not height:
        raise _corrupt()
    if photometric in (0, 1):
        mode = "1" if bits == 1 else ("I;16" if bits == 16 else "L")
    elif photometric == 3:
        mode = "P"
    elif photometric == 5:
        mode = "CMYK"
    else:
        mode = "RGBA" if alpha else "RGB"
    return _Structure(width, height, max_end, frames=max(pages, 1), mode=mode, has_alpha=alpha, has_icc=icc)


def _walk_bmp(d: bytes) -> _Structure:
    n = len(d)
    bf_size, _, off_bits, dib_size = struct.unpack_from("<IIII", d, 2)
    if dib_size == 12:
        width, height, _, bpp = struct.unpack_from("<HHHH", d, 18)
        compression = 0
        image_size = 0
    elif dib_size in (40, 52, 56, 64, 108, 124) and n >= 14 + dib_size:
        width, height, _, bpp, compression, image_size = struct.unpack_from("<iiHHII", d, 18)
    else:
        raise _corrupt()
    height = abs(height)
    if width <= 0 or height <= 0 or off_bits < 14 + dib_size:
        raise _corrupt()
    alpha = False
    if bpp == 32 and dib_size >= 56:
        alpha = struct.unpack_from("<I", d, 14 + 52)[0] != 0
    icc = dib_size == 124 and d[14 + 56 : 14 + 60] in (b"MBED", b"DEBM")
    if image_size == 0 and compression in (0, 3, 6):
        image_size = ((width * bpp + 31) // 32) * 4 * height
    # bfSize is authoritative when plausible; some writers leave it 0, then use the pixel array size.
    end = bf_size if bf_size > off_bits else off_bits + image_size
    if end > n:
        raise _truncated()
    mode = "P" if bpp <= 8 else ("RGBA" if alpha else "RGB")
    return _Structure(width, height, end, mode=mode, has_alpha=alpha, has_icc=icc)


def _walk_heif(d: bytes) -> _Structure:
    n = len(d)
    pos = 0
    while pos + 8 <= n:
        size = int.from_bytes(d[pos : pos + 4], "big")
        if size == 1:
            if pos + 16 > n:
                raise _truncated()
            size = int.from_bytes(d[pos + 8 : pos + 16], "big")
        elif size == 0:
            size = n - pos
        if size < 8:
            raise _corrupt()
        if pos + size > n:
            raise _truncated()
        pos += size
    width = height = 0
    idx = d.find(b"ispe", 0, pos)
    while idx >= 0:
        if idx + 16 <= n:
            w, h = struct.unpack_from(">II", d, idx + 8)
            if w * h > width * height:
                width, height = w, h
        idx = d.find(b"ispe", idx + 4, pos)
    return _Structure(width, height, pos)


_WALKERS = {
    "JPEG": _walk_jpeg,
    "PNG": _walk_png,
    "GIF": _walk_gif,
    "WEBP": _walk_webp,
    "TIFF": _walk_tiff,
    "BMP": _walk_bmp,
    "HEIF": _walk_heif,
}


# ------------------------------------------------------------------------------------ trailing data


def sniff_trailing(trailing: bytes) -> str | None:
    """Classify data appended after the image's logical end. ``None`` when there is none."""
    if not trailing:
        return None
    if not trailing.strip(b"\x00 \t\r\n"):
        return "padding"
    if _find_pe(trailing):
        return "pe"
    elf = trailing.find(b"\x7fELF")
    if elf >= 0 and trailing[elf + 4 : elf + 5] in (b"\x01", b"\x02"):
        return "elf"
    if trailing.startswith((b"PK\x03\x04", b"PK\x05\x06")) or (b"PK\x03\x04" in trailing and b"PK\x05\x06" in trailing):
        return "zip"
    if b"Rar!\x1a\x07" in trailing:
        return "rar"
    if b"7z\xbc\xaf\x27\x1c" in trailing:
        return "7z"
    if b"%PDF-" in trailing:
        return "pdf"
    if _PHP.search(trailing):
        return "php"
    if _HTML.search(trailing):
        return "html"
    if trailing.lstrip(b"\x00 \t\r\n").startswith(b"#!"):
        return "script"
    if trailing.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if trailing.startswith(b"\x89PNG"):
        return "png"
    if trailing[4:8] == b"ftyp":
        return "mp4"
    return "unknown"


def _find_pe(data: bytes) -> bool:
    if data.startswith(b"MZ"):
        return True
    idx = data.find(b"MZ")
    checked = 0
    while idx >= 0 and checked < 256:
        if idx + 0x40 <= len(data):
            lfanew = int.from_bytes(data[idx + 0x3C : idx + 0x40], "little")
            if 0 < lfanew < 4096 and data[idx + lfanew : idx + lfanew + 4] == b"PE\x00\x00":
                return True
        checked += 1
        idx = data.find(b"MZ", idx + 2)
    return False


def quarantine_reason(info: FileInfo) -> str | None:
    """Quarantine code for polyglot uploads (archive/executable/script/HTML appended to the image)."""
    if info.trailing_signature in QUARANTINE_SIGNATURES:
        return f"polyglot_{info.trailing_signature}"
    return None


# ------------------------------------------------------------------------------------------- public


def validate_upload(data: bytes, declared_mime: str | None, config: PipelineConfig) -> FileInfo:
    """Validate an upload without decoding it. Raises :class:`ImageRejected` for bad uploads.

    Polyglot files are *not* rejected here: the returned :class:`FileInfo` carries
    ``trailing_signature`` and :func:`quarantine_reason` tells the caller to quarantine them.
    """
    if not data:
        raise ImageRejected("empty", "The file is empty.")
    if len(data) > config.max_upload_bytes:
        raise ImageRejected("too_large", "The file exceeds the maximum upload size.")
    declared = normalize_mime(declared_mime)
    if declared == "image/svg+xml":
        raise ImageRejected("svg_not_allowed", "SVG images are not accepted.")
    fmt = sniff_format(data, allow_heif=config.allow_heif)
    mime = FORMAT_MIME[fmt]
    if declared is not None and declared != mime:
        raise ImageRejected("mime_mismatch", "The declared file type does not match the file content.")
    try:
        structure = _WALKERS[fmt](data)
    except (struct.error, IndexError, ValueError) as exc:
        raise _corrupt() from exc
    if fmt != "HEIF" or structure.width:
        if structure.width <= 0 or structure.height <= 0:
            raise _corrupt()
        if (
            structure.width * structure.height > config.max_pixels
            or max(structure.width, structure.height) > config.max_side
        ):
            raise ImageRejected("dimensions_exceeded", "The image dimensions exceed the allowed maximum.")
    trailing = data[structure.end :]
    return FileInfo(
        mime=mime,
        format=fmt,
        width=structure.width,
        height=structure.height,
        frames=structure.frames,
        byte_size=len(data),
        mode=structure.mode,
        has_alpha=structure.has_alpha,
        has_icc_profile=structure.has_icc,
        file_sha256=hashlib.sha256(data).hexdigest(),
        trailing_bytes=len(trailing),
        trailing_signature=sniff_trailing(trailing),
    )
