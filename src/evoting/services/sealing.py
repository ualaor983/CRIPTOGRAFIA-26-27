"""Sellado de elementos de Z_P con la clave Kb (AES-256-GCM con AAD de posicion).

Cada elemento se serializa en 32 B big-endian y se cifra ligado a su eleccion y
posicion: moverlo de columna, eleccion o votante hace fallar la etiqueta.
"""

from __future__ import annotations

from evoting.core import scheme
from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm

_OPEN_FAILED_MESSAGE: str = (
    "No se pudo abrir el elemento: clave incorrecta, posición distinta o dato alterado."
)


def control_aad(eid: str, m: int, n: int) -> bytes:
    """AAD de la celda de control: eleccion ``eid``, columna ``m`` y ``n`` filas de voto.

    Lanza: ValueError si ``m`` no esta en [0, N_COLUMNS) o ``n`` no es un entero >= 0.
    """
    if not _is_index(m) or m >= scheme.N_COLUMNS or not _is_index(n):
        raise ValueError("Columna o numero de filas fuera de rango.")
    return _aad(b"control", eid, str(m), str(n))


def mark_aad(eid: str, voter_id: str) -> bytes:
    """AAD de la marca del censo: eleccion ``eid`` e id del votante."""
    return _aad(b"marca", eid, voter_id)


def _is_index(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _aad(domain: bytes, *fields: str) -> bytes:
    # Campos con prefijo de longitud: sin separador no hay colisiones entre campos.
    out = _field(b"evoting/1") + _field(domain)
    for f in fields:
        out += _field(f.encode("utf-8"))
    return out


def _field(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw


def seal_element(kb: bytes, x: int, aad: bytes) -> bytes:
    """Cifra ``x`` (32 B big-endian) con AES-256-GCM, clave ``kb`` y ``aad``.

    Devuelve nonce||cifrado||etiqueta (60 B).
    Lanza: ValueError si ``x`` no esta en [0, P) o ``kb`` no mide 32 B.
    """
    if isinstance(x, bool) or not isinstance(x, int) or not 0 <= x < scheme.P:
        raise ValueError("El elemento debe ser un entero en [0, P).")
    return aes_gcm.encrypt(kb, x.to_bytes(scheme.ELEMENT_SIZE, "big"), aad=aad)


def open_element(kb: bytes, data: bytes, aad: bytes) -> int:
    """Descifra un elemento sellado con ``seal_element`` y devuelve el entero.

    Lanza: DomainError si la clave, el AAD o el dato no cuadran, o el valor no es < P.
    """
    try:
        raw = aes_gcm.decrypt(kb, data, aad=aad)
    except (aes_gcm.AuthenticationError, ValueError):
        raise DomainError(_OPEN_FAILED_MESSAGE) from None
    x = int.from_bytes(raw, "big")
    if len(raw) != scheme.ELEMENT_SIZE or x >= scheme.P:
        raise DomainError(_OPEN_FAILED_MESSAGE)
    return x
