"""Celdas cifradas con Kb: fila de control de la urna y marca del censo.

AES-256-GCM (``crypto.aes_gcm``); cada celda es un entero de 16 B cifrado y en hex.
"""

from __future__ import annotations

from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm

# 2^127 - 1 cabe en 16 bytes.
_CELL_BYTES: int = 16


def seal(kb: bytes, value: int) -> str:
    """Cifra un entero con Kb y lo devuelve en hex (para guardarlo en JSON)."""
    plain = value.to_bytes(_CELL_BYTES, "big")
    cipher = aes_gcm.encrypt(kb, plain)
    return cipher.hex()


def unseal(kb: bytes, cell: str) -> int:
    """Descifra una celda en hex y devuelve el entero.

    Lanza: DomainError si la celda esta alterada o Kb no es la correcta.
    """
    try:
        cipher = bytes.fromhex(cell)
        plain = aes_gcm.decrypt(kb, cipher)
        return int.from_bytes(plain, "big")
    except (ValueError, aes_gcm.AuthenticationError):
        raise DomainError("La celda esta alterada o Kb no es la correcta") from None


def seal_row(kb: bytes, values: list[int]) -> list[str]:
    """``seal`` aplicado a cada valor de la fila."""
    return [seal(kb, value) for value in values]


def unseal_row(kb: bytes, cells: list[str]) -> list[int]:
    """``unseal`` aplicado a cada celda de la fila."""
    return [unseal(kb, cell) for cell in cells]
