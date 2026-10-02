# Third-party notices

Angel Engine vendors the following files. Package dependencies (Python and npm) are declared in
`backend/pyproject.toml` and `frontend/package.json` and keep their own licences.

| Component | Where | Licence | Source |
|---|---|---|---|
| YuNet face **detection** model (`face_detection_yunet_2023mar.onnx`) | `backend/src/angel_engine/models/` | MIT — © 2020 Shiqi Yu (`LICENSE.yunet.txt`) | OpenCV model zoo |
| NanoDet-Plus object detection model (`object_detection_nanodet_2022nov.onnx`) | `backend/src/angel_engine/models/` | Apache-2.0 (`LICENSE.nanodet.txt`) | OpenCV model zoo |
| Natural Earth admin-0/admin-1 boundaries and populated places (simplified) | `backend/src/angel_engine/data/` | Public domain | Natural Earth v5.1.2 |
| Common-password list (filtered NCSC 100k list) | `backend/src/angel_engine/data/common-passwords.txt.gz` | MIT | SecLists (Daniel Miessler) |

Model checksums are pinned in `backend/src/angel_engine/models/MANIFEST.json` and verified before use. No
face-recognition, face-embedding or demographic-attribute model is, or may be, included.

Optional HEIC support (`heif` extra) installs `pillow-heif`, whose wheels bundle libheif (LGPL-3.0) and x265
(GPL-2.0); it is disabled by default.
