"""Demostracion por consola de la eleccion completa (``python -m evoting.ui.console``)."""

from __future__ import annotations

from pathlib import Path

from evoting.core.errors import DomainError
from evoting.services import election


def main() -> int:
    """Lanza una eleccion de 10 votantes y muestra el resultado; devuelve 0 si va bien."""
    votes = {
        "V01": "si", "V02": "si", "V03": "si", "V04": "si", "V05": "si",
        "V06": "si", "V07": "no", "V08": "no", "V09": "no", "V10": "invalido",
    }
    try:
        result = election.run_election(votes, Path("data"))
    except DomainError as error:
        print("Error:", error)
        return 1

    print("Resultado por columna:", result)
    print("Si:", result.count("si"))
    print("No:", result.count("no"))
    print("Nulos:", result.count("nulo"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
