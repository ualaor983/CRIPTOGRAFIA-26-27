"""Punto de entrada de la aplicacion de escritorio (``python -m evoting``)."""

from __future__ import annotations

from evoting.ui import app


def main() -> int:
    """Abre la ventana y devuelve el codigo de salida de la aplicacion."""
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
