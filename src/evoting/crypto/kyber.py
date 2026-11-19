"""Kyber (ML-KEM-768, FIPS 203) sobre ``bytes``: par de claves, encapsular y desencapsular.

Usa ``mlkem`` de ``cryptography``. Tamanos con k = 3, q = 3329, n = 256:
- clave publica: 1184 B (t y la semilla rho de la que se genera la matriz A)
- clave privada: 64 B (semilla d || z; de ella se regenera todo el par)
- capsula c = (u, v): 1088 B
- clave compartida K: 32 B, es decir, una clave AES-256

Por dentro, encapsular es el cifrado Kyber de los apuntes (T3 3.7): se elige un m
aleatorio de 256 bits, (K, r) = G(m || H(pk)) y c = (u, v) es el cifrado de m con r.
Desencapsular descifra c, rehace K y vuelve a cifrar para comprobar que c es correcto.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import mlkem

from evoting.crypto import randomness

PUBLIC_KEY_SIZE: int = 1184
SECRET_KEY_SIZE: int = 64
CAPSULE_SIZE: int = 1088
SHARED_KEY_SIZE: int = 32


def generate_keypair() -> tuple[bytes, bytes]:
    """Par nuevo: (clave publica, clave privada).

    La privada es la semilla de 64 B del estandar; sale de ``randomness`` como el
    resto de claves del proyecto.
    """
    seed = randomness.random_bytes(SECRET_KEY_SIZE)
    secret_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    public_key = secret_key.public_key().public_bytes_raw()
    return public_key, seed


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Lo hace el emisor: devuelve (K, c), una clave AES-256 nueva y su capsula.

    K se queda en el emisor; c viaja al dueno de ``public_key``. El m aleatorio
    interno lo elige la libreria. Lanza: ValueError si la clave publica no es valida.
    """
    receiver_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
    key, capsule = receiver_key.encapsulate()
    return key, capsule


def decapsulate(secret_key: bytes, capsule: bytes) -> bytes:
    """Lo hace el receptor: recupera K de la capsula ``c`` con su clave privada.

    Si la capsula esta alterada no hay error: sale una K distinta (asi lo fija el
    estandar) y es el descifrado AES-GCM posterior el que lo detecta.
    Lanza: ValueError si la clave o la capsula no tienen el tamano correcto.
    """
    own_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(secret_key)
    return own_key.decapsulate(capsule)
