"""Angel Engine never performs facial recognition: no face-recognition library, recognizer API or model may be
added to the code base, its dependencies or the vendored model directory."""

from __future__ import annotations

import ast
import json
import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "angel_engine"
BANNED_MODULES = {
    "face_recognition", "face_recognition_models", "dlib", "deepface", "insightface", "facenet", "facenet_pytorch",
    "arcface", "retinaface", "mtcnn", "compreface", "pyfacer", "facexlib", "kairos", "rekognition",
}  # fmt: skip
#: Recognition / embedding / attribute APIs of otherwise allowed libraries.
BANNED_CALLS = re.compile(
    r"FaceRecognizerSF|cv2\.face\b|LBPHFaceRecognizer|EigenFaceRecognizer|FisherFaceRecognizer|"
    r"detect_faces\(.*Attributes|search_faces|index_faces|compare_faces|FACE_DETECTION|face_embedding"
)
BANNED_MODEL_WORDS = {
    "sface",
    "arcface",
    "facenet",
    "recognition",
    "recognizer",
    "embedding",
    "embeddings",
    "age",
    "gender",
    "emotion",
    "ethnicity",
    "race",
}


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_no_face_recognition_imports_or_apis() -> None:
    offenders = []
    for path in SRC.rglob("*.py"):
        if banned := _imports(path) & BANNED_MODULES:
            offenders.append(f"{path.relative_to(ROOT)}: imports {sorted(banned)}")
        if match := BANNED_CALLS.search(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(ROOT)}: uses {match.group(0)!r}")
    assert not offenders, offenders


def test_no_face_recognition_dependencies() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared += extra
    names = {re.split(r"[\s\[<>=!~;]", dep, maxsplit=1)[0].lower().replace("-", "_") for dep in declared}
    assert not names & BANNED_MODULES


def test_only_manifest_models_are_vendored() -> None:
    models = SRC / "models"
    manifest = json.loads((models / "MANIFEST.json").read_text(encoding="utf-8"))
    onnx = {p.name for p in models.iterdir() if p.suffix in (".onnx", ".pb", ".tflite", ".caffemodel", ".pt", ".bin")}
    assert onnx == set(manifest)
    for name in onnx:
        assert not set(re.split(r"[^a-z0-9]+", name.lower())) & BANNED_MODEL_WORDS, name
