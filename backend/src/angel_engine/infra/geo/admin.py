"""Generalize a GPS position to country / first-level administrative region.

Precise coordinates never leave this function: callers receive only names and ISO codes. The
polygons are the vendored, simplified Natural Earth datasets built by ``scripts/build_geodata.py``
(public domain; boundaries accurate to roughly 2 km).

Rules:

* point inside exactly one admin-1 polygon → ``resolved`` (country + region);
* the region is smaller than :data:`MIN_REGION_KM2` (cities, boroughs, small districts) or the country is
  a city-state/microstate → ``country_only`` (a small region would be too precise);
* ambiguous admin-1 hit (simplification overlap) inside a single country → ``country_only``;
* otherwise the admin-0 polygons decide → ``country_only`` or ``unresolved``. Points outside every
  polygon (sea, simplification gaps) are never snapped to the nearest one.
"""

from __future__ import annotations

import gzip
import json
import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from angel_engine.images.types import GeneralizedLocation

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
ADMIN1_FILE = "ne_admin1.geojson.gz"
ADMIN0_FILE = "ne_admin0.geojson.gz"
MIN_REGION_KM2 = 2000
#: City-states and microstates: never resolved below country level.
CITY_STATES = frozenset({"SG", "MC", "VA", "SM", "HK", "MO", "GI", "AD", "LI", "MT", "BH", "LU"})


@dataclass(frozen=True, slots=True)
class _Region:
    cc: str | None
    country: str | None
    name: str | None
    code: str | None
    area_km2: int


@dataclass(frozen=True, slots=True)
class _Index:
    admin1_tree: Any
    admin1: tuple[_Region, ...]
    admin0_tree: Any
    admin0: tuple[tuple[str | None, str], ...]


_lock = threading.Lock()
_index: _Index | None = None


def _load_features(path: Path) -> list[dict[str, Any]]:
    payload: dict[str, Any] = json.loads(gzip.decompress(path.read_bytes()))
    features: list[dict[str, Any]] = payload["features"]
    return features


def _build_index() -> _Index:
    import shapely
    from shapely.geometry import shape

    admin1_geoms: list[Any] = []
    admin1: list[_Region] = []
    for feature in _load_features(DATA_DIR / ADMIN1_FILE):
        p = feature["properties"]
        admin1_geoms.append(shape(feature["geometry"]))
        admin1.append(_Region(p.get("cc"), p.get("country"), p.get("name"), p.get("code"), int(p.get("area_km2") or 0)))
    admin0_geoms: list[Any] = []
    admin0: list[tuple[str | None, str]] = []
    for feature in _load_features(DATA_DIR / ADMIN0_FILE):
        p = feature["properties"]
        admin0_geoms.append(shape(feature["geometry"]))
        admin0.append((p.get("cc"), str(p.get("name") or "")))
    shapely.prepare(admin1_geoms)
    shapely.prepare(admin0_geoms)
    return _Index(shapely.STRtree(admin1_geoms), tuple(admin1), shapely.STRtree(admin0_geoms), tuple(admin0))


def _get_index() -> _Index:
    global _index  # noqa: PLW0603 - lazily built, process-wide immutable index
    if _index is None:
        with _lock:
            if _index is None:
                _index = _build_index()
    return _index


def _country_only(cc: str | None, name: str | None) -> GeneralizedLocation:
    return GeneralizedLocation(status="country_only", country_code=cc, country_name=name)


def generalize(lat: float, lon: float) -> GeneralizedLocation:
    """Map a WGS84 position to country/admin-1 names. The coordinates are not retained or returned."""
    if not (math.isfinite(lat) and math.isfinite(lon)) or not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return GeneralizedLocation(status="unresolved")
    from shapely.geometry import Point

    index = _get_index()
    point = Point(lon, lat)
    regions = [index.admin1[int(i)] for i in index.admin1_tree.query(point, predicate="intersects")]
    if len(regions) == 1:
        region = regions[0]
        if region.cc in CITY_STATES or region.area_km2 < MIN_REGION_KM2 or not region.name:
            return _country_only(region.cc, region.country)
        return GeneralizedLocation(
            status="resolved",
            country_code=region.cc,
            country_name=region.country,
            region_code=region.code,
            region_name=region.name,
        )
    if regions and len({(r.cc, r.country) for r in regions}) == 1:
        return _country_only(regions[0].cc, regions[0].country)
    countries = {index.admin0[int(i)] for i in index.admin0_tree.query(point, predicate="intersects")}
    if len(countries) == 1:
        cc, name = countries.pop()
        return _country_only(cc, name)
    return GeneralizedLocation(status="unresolved")
