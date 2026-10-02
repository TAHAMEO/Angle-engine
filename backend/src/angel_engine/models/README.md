# Vendored models

Both files come from the OpenCV model zoo and are verified against `MANIFEST.json` (SHA-256) before use.

| File | Use | Licence |
|---|---|---|
| `face_detection_yunet_2023mar.onnx` | YuNet face **detection** — count and bounding boxes only, used to blur faces and to show "A face was detected in the image. Angel Engine does not perform facial identification." Landmarks and embeddings are never kept. | MIT |
| `object_detection_nanodet_2022nov.onnx` | NanoDet-Plus generic object detection (80 COCO classes) for visual clues. `person` detections are only counted. | Apache-2.0 |

Licence texts: `LICENSE.yunet.txt` (MIT, © 2020 Shiqi Yu) and `LICENSE.nanodet.txt` (Apache-2.0).

No face-recognition, face-embedding or demographic-attribute model is, or may be, included.
