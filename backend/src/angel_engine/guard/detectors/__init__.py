"""Sensitive-data detectors, one module per family. :data:`DETECTORS` is the ordered registry."""

from __future__ import annotations

from angel_engine.guard.detectors import (
    address,
    bank,
    coordinates,
    credentials,
    dob,
    email,
    medical,
    national_id,
    payment,
    phone,
    urls,
    vehicle,
    wifi,
)
from angel_engine.guard.detectors.base import Detection, Detector, Scan

DETECTORS: tuple[Detector, ...] = (
    urls.detect,
    credentials.detect,
    wifi.detect,
    national_id.detect,
    bank.detect,
    payment.detect,
    email.detect,
    coordinates.detect,
    dob.detect,
    vehicle.detect,
    phone.detect,
    address.detect,
    medical.detect,
)

__all__ = ["DETECTORS", "Detection", "Detector", "Scan"]
