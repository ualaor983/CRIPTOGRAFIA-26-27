"""AES-256-GCM sobre ``bytes``: generar clave, cifrar, descifrar y leer el nonce.

Formato del dato cifrado: ``nonce (12 B) || cifrado (n B) || etiqueta (16 B)``.
Usa ``AESGCM`` de ``cryptography``; no hay datos asociados ni límite de tamaño propio.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from evoting.crypto import randomness

# AES-256.
KEY_SIZE: int = 32

# 96 bits, la longitud recomendada por NIST SP 800-38D.
NONCE_SIZE: int = 12

# Etiqueta GCM completa, sin truncar.
TAG_SIZE: int = 16

# Sobrecoste fijo (nonce + etiqueta) y tamaño mínimo de un dato cifrado válido.
OVERHEAD: int = NONCE_SIZE + TAG_SIZE


class AuthenticationError(Exception):
    """La etiqueta GCM no verifica: clave incorrecta o dato cifrado alterado."""


def generate_key() -> bytes:
    """Clave AES-256 nueva: 32 bytes de ``randomness.random_bytes``.

    Protege la confidencialidad: todo descansa en que la clave sea impredecible.
    """
    return randomness.random_bytes(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM, clave 32 B, nonce 12 B nuevo por llamada; devuelve nonce||cifrado||tag.

    Protege confidencialidad (salvo la longitud) e integridad del dato cifrado.
    Lanza: ValueError si ``key`` no mide 32 bytes; OverflowError (de la librería)
    si ``plaintext`` supera 2**31 - 1 bytes.
    """
    _check_key(key)
    # Nonce generado aquí y no recibido: repetir (clave, nonce) en GCM revela el XOR
    # de los contenidos y permite falsificar etiquetas.
    nonce = randomness.random_bytes(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, data: bytes) -> bytes:
    """Descifra nonce||cifrado||etiqueta con AES-256-GCM y devuelve el contenido.

    No entrega nada, ni parcial, si la etiqueta no verifica.
    Lanza: ValueError si ``key`` no mide 32 bytes o ``data`` menos de 28;
    AuthenticationError si la etiqueta no verifica (clave errónea o dato alterado).
    """
    _check_key(key)
    _check_data(data)
    cipher = AESGCM(key)
    nonce = data[:NONCE_SIZE]
    try:
        plaintext = cipher.decrypt(nonce, data[NONCE_SIZE:], None)
    except InvalidTag:
        # "from None" y mensaje fijo: no se encadena la excepción ni se filtra nada.
        raise AuthenticationError(
            "La etiqueta de autenticación no verifica: "
            "clave incorrecta o dato cifrado alterado."
        ) from None
    return plaintext


def nonce_of(data: bytes) -> bytes:
    """Los 12 primeros bytes de un dato cifrado; no verifica su autenticidad.

    Lanza: ValueError si ``data`` mide menos de 28 bytes.
    """
    _check_data(data)
    return data[:NONCE_SIZE]


def _check_key(key: bytes) -> None:
    # Solo AES-256, aunque AESGCM aceptaría también 16 y 24 bytes.
    if len(key) != KEY_SIZE:
        raise ValueError(f"La clave debe medir exactamente {KEY_SIZE} bytes (AES-256).")


def _check_data(data: bytes) -> None:
    if len(data) < OVERHEAD:
        raise ValueError(
            f"El dato cifrado debe medir al menos {OVERHEAD} bytes (nonce y etiqueta)."
        )
