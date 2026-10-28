"""Almacen JSON versionado: cada version es una carpeta y `actual.json` la confirma."""

import json
import os
import shutil
from collections.abc import Mapping
from pathlib import Path

from evoting.core.errors import DomainError

_POINTER = "actual.json"


def _version_dir(root: Path, version: int) -> Path:
    return root / f"v{version:04d}"


def _write_file(path: Path, text: str) -> None:
    """Escribe `text` en un temporal contiguo y lo mueve con `os.replace`."""
    # En Windows no hay fsync de directorio: limitacion conocida de la durabilidad.
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _current_version(root: Path) -> int:
    pointer = root / _POINTER
    if not pointer.is_file():
        return 0
    try:
        version = json.loads(pointer.read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DomainError("La version vigente no es legible.") from exc
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise DomainError("La version vigente no es legible.")
    return version


def write_version(root: Path, version: int, files: Mapping[str, object]) -> None:
    """Crea `vNNNN/` con los ficheros y, al final, apunta `actual.json` a ella.

    `version` debe ser la vigente + 1 (1 si no hay). El `os.replace` del puntero es el
    punto de confirmacion: si algo falla antes, se borra la carpeta nueva y la version
    anterior sigue vigente.
    Lanza: DomainError si la version no es la siguiente, un nombre no es `*.json`, un
    dato no es serializable o falla el IO.
    """
    root = Path(root)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise DomainError("Numero de version no valido.")
    for name in files:
        if Path(name).name != name or not name.endswith(".json") or name == _POINTER:
            raise DomainError("Nombre de fichero no valido.")
    try:
        texts = {n: json.dumps(d, ensure_ascii=False, indent=2) for n, d in files.items()}
    except (TypeError, ValueError) as exc:
        raise DomainError("Contenido no serializable.") from exc
    vdir = _version_dir(root, version)
    if vdir.exists():
        raise DomainError("La version ya existe.")
    if version != _current_version(root) + 1:
        raise DomainError("La version no es la siguiente a la vigente.")
    try:
        root.mkdir(parents=True, exist_ok=True)
        vdir.mkdir()  # exclusivo: no pisa una version existente
    except FileExistsError:
        raise DomainError("La version ya existe.") from None
    except OSError as exc:
        raise DomainError("No se pudo preparar el almacen.") from exc
    try:
        for name, text in texts.items():
            _write_file(vdir / name, text)
        _write_file(root / _POINTER, json.dumps({"version": version}))
    except BaseException as exc:
        shutil.rmtree(vdir, ignore_errors=True)
        (root / (_POINTER + ".tmp")).unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise DomainError("No se pudo guardar la version.") from exc
        raise


def read_current(root: Path) -> tuple[int, dict[str, object]]:
    """Devuelve el numero de la version vigente y el contenido de sus ficheros.

    Lanza: DomainError si no hay `actual.json`, falta la carpeta o esta vacia, o no es
    legible.
    """
    root = Path(root)
    if not (root / _POINTER).is_file():
        raise DomainError("No hay version vigente.")
    version = _current_version(root)
    paths = sorted(_version_dir(root, version).glob("*.json"))
    if not paths:
        raise DomainError("La version vigente no existe o esta vacia.")
    try:
        out = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in paths}
    except (OSError, ValueError) as exc:
        raise DomainError("La version vigente no es legible.") from exc
    return version, out
