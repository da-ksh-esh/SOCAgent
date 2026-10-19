"""Project paths and JSON loading (no hard-coded absolute paths)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


@lru_cache(maxsize=32)
def _load(path: str, mtime: float):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_json(name: str, data_dir: str | Path = DATA_DIR):
    """Load data/<name>; cached until the file changes on disk."""
    path = Path(data_dir) / name
    return _load(str(path), path.stat().st_mtime)
