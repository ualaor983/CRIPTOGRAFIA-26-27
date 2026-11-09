"""Lectura y escritura de los ficheros publicos (urna y censo) en JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path


def save(path: Path, data: dict) -> None:
    """Guarda ``data`` en ``path`` de forma atomica: o queda el fichero nuevo o el viejo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load(path: Path) -> dict:
    """Lee un JSON guardado con ``save``."""
    return json.loads(path.read_text(encoding="utf-8"))