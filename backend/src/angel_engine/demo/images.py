"""Synthetic demo images (generated at seed time; no real photographs and no real faces)."""

from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont

#: The fixture face detector (development/e2e only) reports pure-magenta areas as a detected "face".
MAGENTA = (255, 0, 255)


def _jpeg(img: Image.Image, exif: Image.Exif | None = None, quality: int = 90) -> bytes:
    buf = io.BytesIO()
    if exif is not None:
        img.save(buf, format="JPEG", quality=quality, exif=exif)
    else:
        img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def storefront(*, marker: bool = True, size: tuple[int, int] = (1600, 1000), quality: int = 90) -> bytes:
    """A fictional coffee-shop sign with visible text, a domain, a handle and camera EXIF (GPS in Lisbon)."""
    img = Image.new("RGB", (1600, 1000), (40, 60, 80))
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
    if marker:  # stand-in for a person in the photo (detected and blurred, never identified)
        d.rectangle([1300, 560, 1460, 760], fill=MAGENTA)
    if size != img.size:
        img = img.resize(size)
    exif = Image.Exif()
    exif[271] = "DemoCam"
    exif[272] = "DC-100"
    exif[305] = "Adobe Photoshop 26.0"
    exif[306] = "2026:06:20 18:00:00"
    exif[315] = "Demo Photographer"  # identifying owner field: kept only as a presence flag
    ex = exif.get_ifd(0x8769)
    ex[36867] = "2026:06:14 09:12:33"
    ex[36881] = "+01:00"
    ex[42033] = "DC100-0004471"  # body serial: identifying, redacted
    ex[33437] = 2.8
    gps = exif.get_ifd(0x8825)
    gps[1], gps[2] = "N", (38.0, 43.0, 20.28)
    gps[3], gps[4] = "W", (9.0, 8.0, 21.48)
    return _jpeg(img, exif, quality)


def flyer() -> bytes:
    """A fictional event flyer without metadata."""
    img = Image.new("RGB", (1200, 1600), (250, 246, 238))
    d = ImageDraw.Draw(img)
    title = ImageFont.load_default(size=80)
    body = ImageFont.load_default(size=44)
    d.rectangle([60, 60, 1140, 360], fill=(32, 72, 96))
    d.text((100, 120), "NORTHWIND", font=title, fill=(250, 246, 238))
    d.text((100, 230), "SECOND ROASTERY OPENING", font=body, fill=(250, 246, 238))
    d.text((100, 460), "Saturday 14 March 2026", font=body, fill=(30, 30, 30))
    d.text((100, 560), "Porto Riverside Market", font=body, fill=(30, 30, 30))
    d.text((100, 660), "#northwindporto", font=body, fill=(30, 30, 30))
    d.text((100, 760), "www.northwind-coffee.example/porto", font=body, fill=(30, 30, 30))
    for i in range(6):
        d.ellipse([140 + i * 160, 1000, 260 + i * 160, 1120], fill=((i * 40) % 255, 90, 140))
    return _jpeg(img)
