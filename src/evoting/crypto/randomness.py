"""Aleatoriedad criptografica: punto unico de bytes aleatorios del proyecto.

Usa ``secrets.token_bytes`` (CSPRNG del sistema operativo), sin fuente alternativa.
"""

from __future__ import annotations

import secrets


def random_bytes(n: int) -> bytes:
    """``n`` bytes del CSPRNG del SO (``secrets.token_bytes``); origen de claves y nonces.

    Lanza: ValueError si ``n`` no es un ``int`` positivo (``bool`` incluido);
    OSError si el SO no puede dar aleatoriedad (no hay fuente alternativa).
    """
    # Se valida antes porque token_bytes(0) daría b"" y token_bytes(None) 32 bytes
    # por defecto; bool se excluye por ser subclase de int.
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise ValueError("n debe ser un entero positivo")
    return secrets.token_bytes(n)
