#!/usr/bin/env python3
"""Build the compact Natural Earth datasets vendored in ``backend/src/angel_engine/data/``.

Angel Engine never returns precise GPS coordinates: EXIF positions are generalized to country and
first-level administrative region (admin-1) with these polygons (see ``angel_engine.infra.geo``).

Source: Natural Earth (public domain, https://www.naturalearthdata.com/about/terms-of-use/), fetched
from the pinned ``v5.1.2`` tag of https://github.com/nvkelso/natural-earth-vector and verified
against the SHA-256 checksums below.

Outputs (deterministic, gzip ``mtime=0``):

* ``ne_admin1.geojson.gz`` — admin-1 polygons simplified with ``simplify(0.02, preserve_topology=True)``
  (≈2 km), snapped to a 0.001° grid. Properties: ``cc`` (ISO 3166-1 alpha-2), ``country``, ``name``,
  ``code`` (ISO 3166-2 when well-formed) and ``area_km2`` (spherical equal-area estimate computed on
  the *unsimplified* geometry).
* ``ne_admin0.geojson.gz`` — countries (1:50m), same treatment. Properties: ``cc``, ``name``.
* ``world_places.json.gz`` — country names and major world cities (capitals, Natural Earth "world
  cities"/megacities, scale rank ≤ 2) used to recognise broad place names in visible text.

Usage::

    backend/.venv/bin/python scripts/build_geodata.py [--source-dir DIR] [--out-dir DIR]

``--source-dir`` reads previously downloaded GeoJSON files instead of fetching them.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import sys
import urllib.request
from typing import Any

import numpy as np
import shapely
from shapely.geometry import mapping, shape

NE_TAG = "v5.1.2"
NE_BASE = f"https://raw.githubusercontent.com/nvkelso/natural-earth-vector/{NE_TAG}/geojson/"
SOURCES: dict[str, str] = {
    "ne_10m_admin_1_states_provinces.geojson": "22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5",
    "ne_50m_admin_0_countries.geojson": "3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb",
    "ne_10m_populated_places_simple.geojson": "fd3fa867a320cbd5c5b6bb5bc550afeec2939fb2cef688e508007282a55ac42f",
}
SIMPLIFY_TOLERANCE = 0.02  # degrees (≈2.2 km at the equator)
GRID = 0.001  # coordinates rounded to 3 decimals
EARTH_RADIUS_KM = 6371.0088
ISO2 = re.compile(r"^[A-Z]{2}$")
ISO3166_2 = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")

REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "backend" / "src" / "angel_engine" / "data"


def _fetch(name: str, source_dir: pathlib.Path | None) -> dict[str, Any]:
    if source_dir is not None:
        raw = (source_dir / name).read_bytes()
    else:
        url = NE_BASE + name
        if not url.startswith("https://raw.githubusercontent.com/"):
            raise SystemExit(f"refusing unexpected source URL {url}")
        with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - pinned https URL
            raw = resp.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCES[name]:
        raise SystemExit(f"checksum mismatch for {name}: {digest}")
    data: dict[str, Any] = json.loads(raw)
    return data


def _area_km2(geom: Any) -> float:
    """Spherical area via the Lambert cylindrical equal-area projection."""

    def project(coords: Any) -> Any:
        out = coords.copy()
        out[:, 0] = EARTH_RADIUS_KM * np.radians(coords[:, 0])
        out[:, 1] = EARTH_RADIUS_KM * np.sin(np.radians(coords[:, 1]))
        return out

    return float(shapely.transform(geom, project).area)


def _compact(geom: Any) -> Any | None:
    geom = shapely.make_valid(geom)
    simplified = geom.simplify(SIMPLIFY_TOLERANCE, preserve_topology=True)
    snapped = shapely.set_precision(simplified, GRID)
    polygons = [g for g in shapely.get_parts(snapped) if g.geom_type in ("Polygon", "MultiPolygon") and not g.is_empty]
    if not polygons:
        return None
    merged = shapely.union_all(polygons) if len(polygons) > 1 else polygons[0]
    return None if merged.is_empty else merged


def _round(coords: Any) -> Any:
    if coords and isinstance(coords[0], (int, float)):
        return [round(float(coords[0]), 3), round(float(coords[1]), 3)]
    return [_round(c) for c in coords]


def _feature(geom: Any, props: dict[str, Any]) -> dict[str, Any]:
    m = mapping(geom)
    geometry = {"type": m["type"], "coordinates": _round(m["coordinates"])}
    return {"type": "Feature", "properties": props, "geometry": geometry}


def _write_gz(path: pathlib.Path, obj: Any) -> int:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    data = gzip.compress(raw, compresslevel=9, mtime=0)
    path.write_bytes(data)
    return len(data)


def _country_code(props: dict[str, Any]) -> str | None:
    for key in ("ISO_A2", "ISO_A2_EH", "WB_A2"):
        value = str(props.get(key) or "")
        if ISO2.match(value):
            return value
    return None


def build(source_dir: pathlib.Path | None, out_dir: pathlib.Path) -> None:
    admin0 = _fetch("ne_50m_admin_0_countries.geojson", source_dir)
    admin1 = _fetch("ne_10m_admin_1_states_provinces.geojson", source_dir)
    places = _fetch("ne_10m_populated_places_simple.geojson", source_dir)

    a3_to_cc: dict[str, str] = {}
    country_features: list[dict[str, Any]] = []
    country_names: set[tuple[str, str]] = set()
    for feature in admin0["features"]:
        p = feature["properties"]
        cc = _country_code(p)
        name = str(p.get("NAME") or p.get("ADMIN") or "").strip()
        if cc:
            for key in ("ADM0_A3", "ISO_A3", "ISO_A3_EH", "SOV_A3", "GU_A3"):
                if p.get(key) and str(p[key]) != "-99":
                    a3_to_cc.setdefault(str(p[key]), cc)
            for key in ("NAME", "NAME_LONG", "ADMIN", "NAME_EN", "NAME_SORT"):
                alias = str(p.get(key) or "").strip()
                if alias and len(alias) >= 4:
                    country_names.add((alias, cc))
        geom = _compact(shape(feature["geometry"]))
        if geom is None or not name:
            continue
        country_features.append(_feature(geom, {"cc": cc, "name": name}))
    country_features.sort(key=lambda f: (f["properties"]["cc"] or "~", f["properties"]["name"]))

    region_features: list[dict[str, Any]] = []
    for feature in admin1["features"]:
        p = feature["properties"]
        cc = str(p.get("iso_a2") or "")
        if not ISO2.match(cc):
            cc = a3_to_cc.get(str(p.get("adm0_a3") or ""), "")
        original = shapely.make_valid(shape(feature["geometry"]))
        geom = _compact(original)
        if geom is None:
            continue
        code = str(p.get("iso_3166_2") or "")
        props = {
            "cc": cc or None,
            "country": str(p.get("admin") or "").strip() or None,
            "name": str(p.get("name") or "").strip() or None,
            "code": code if ISO3166_2.match(code) else None,
            "area_km2": round(_area_km2(original)),
        }
        region_features.append(_feature(geom, props))
    region_features.sort(
        key=lambda f: (f["properties"]["cc"] or "~", f["properties"]["code"] or "~", f["properties"]["name"] or "")
    )

    cities: set[tuple[str, str]] = set()
    for feature in places["features"]:
        p = feature["properties"]
        major = p.get("worldcity") == 1 or p.get("megacity") == 1 or p.get("adm0cap") == 1
        if not major and int(p.get("scalerank") or 99) > 2:
            continue
        cc = str(p.get("iso_a2") or "")
        if not ISO2.match(cc):
            cc = a3_to_cc.get(str(p.get("adm0_a3") or ""), "")
        for key in ("name", "nameascii"):
            name = str(p.get(key) or "").strip()
            if name and len(name) >= 4:
                cities.add((name, cc))

    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"source": f"Natural Earth {NE_TAG} (public domain)", "tolerance_deg": SIMPLIFY_TOLERANCE, "grid_deg": GRID}
    sizes = {
        "ne_admin0.geojson.gz": _write_gz(
            out_dir / "ne_admin0.geojson.gz", {"type": "FeatureCollection", "meta": meta, "features": country_features}
        ),
        "ne_admin1.geojson.gz": _write_gz(
            out_dir / "ne_admin1.geojson.gz", {"type": "FeatureCollection", "meta": meta, "features": region_features}
        ),
        "world_places.json.gz": _write_gz(
            out_dir / "world_places.json.gz",
            {"meta": meta, "countries": sorted(country_names), "cities": sorted(cities)},
        ),
    }
    for name, size in sizes.items():
        digest = hashlib.sha256((out_dir / name).read_bytes()).hexdigest()
        sys.stdout.write(f"{name}\t{size} bytes\t{digest}\n")
    sys.stdout.write(f"{len(country_features)} countries, {len(region_features)} regions, {len(cities)} city names\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--source-dir", type=pathlib.Path, default=None)
    parser.add_argument("--out-dir", type=pathlib.Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    build(args.source_dir, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
