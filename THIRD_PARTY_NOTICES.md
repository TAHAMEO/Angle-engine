# Third-party notices

## Vendored files

Angel Engine includes the following third-party files in this repository.

| Component | Where | Licence | Source |
|---|---|---|---|
| YuNet face **detection** model (`face_detection_yunet_2023mar.onnx`) | `backend/src/angel_engine/models/` | MIT — © 2020 Shiqi Yu (`LICENSE.yunet.txt`) | OpenCV model zoo |
| NanoDet-Plus object detection model (`object_detection_nanodet_2022nov.onnx`) | `backend/src/angel_engine/models/` | Apache-2.0 (`LICENSE.nanodet.txt`) | OpenCV model zoo |
| Natural Earth admin-0/admin-1 boundaries and populated places (simplified) | `backend/src/angel_engine/data/` | Public domain | Natural Earth v5.1.2 |
| Common-password list (filtered NCSC 100k list) | `backend/src/angel_engine/data/common-passwords.txt.gz` | MIT | SecLists (Daniel Miessler) |
| Inter variable font (Latin subset, normal and italic) | `frontend/src/app/fonts/` | SIL Open Font License 1.1 (`LICENSE-Inter.txt`) — © 2016 The Inter Project Authors | rsms/inter via Fontsource |
| JetBrains Mono variable font (Latin subset) | `frontend/src/app/fonts/` | SIL Open Font License 1.1 (`LICENSE-JetBrainsMono.txt`) — © 2020 The JetBrains Mono Project Authors | JetBrains/JetBrainsMono via Fontsource |

Model checksums are pinned in `backend/src/angel_engine/models/MANIFEST.json` and verified before use. No
face-recognition, face-embedding or demographic-attribute model is, or may be, included.

## Package dependencies

Python and npm dependencies are declared in `backend/pyproject.toml` and `frontend/package.json` (exact versions
in `frontend/pnpm-lock.yaml`) and keep their own licences — predominantly MIT, BSD, Apache-2.0, ISC and PSF.
Notable ones: FastAPI, SQLAlchemy, Alembic, Pydantic (MIT); asyncpg, cryptography, OpenCV, Tesseract/pytesseract,
phonenumbers, trafilatura (Apache-2.0); Pillow (MIT-CMU); WeasyPrint, Jinja2, httpx, Protego, pypdf, Shapely
(BSD); dnspython (ISC); Next.js, React, Radix UI, TanStack Query, React Flow, Recharts (MIT); dagre (MIT).

Generate complete, version-exact lists for a release with:

```bash
cd backend && .venv/bin/pip install pip-licenses && .venv/bin/pip-licenses --format=markdown --with-urls
cd frontend && pnpm licenses list --prod
```

Optional HEIC support (`heif` extra) installs `pillow-heif`, whose wheels bundle libheif (LGPL-3.0) and x265
(GPL-2.0); it is disabled by default.

## Container images used by the deployment

The Compose deployment runs these images unmodified as separate services; they are not part of Angel Engine's
code and are distributed by their publishers under their own terms: PostgreSQL (PostgreSQL License), ClamAV
(GPL-2.0), Caddy (Apache-2.0), Redis (Redis 7.4 and later: RSALv2 / SSPLv1 — internal use is permitted; operators
who prefer an OSI-approved licence can substitute Valkey, BSD-3-Clause), Python and Node.js base images (various
open-source licences). The backend image installs Tesseract OCR (Apache-2.0) and Pango/HarfBuzz (LGPL/MIT) from
Debian packages.
