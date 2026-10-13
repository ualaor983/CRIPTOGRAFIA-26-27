"""Cifrado con clave de sesión (AES-256-GCM): generar clave, cifrar y descifrar.

La clave se maneja como 64 caracteres hexadecimales; los mensajes de texto cifrados,
como Base64 en una sola línea; los ficheros, con un tope de 500 MiB.
Dato cifrado: ``nonce (12 B) || cifrado || etiqueta (16 B)``, es decir, +28 B.
Todo fallo que provoca el usuario es un ``DomainError`` con un aviso de texto fijo,
sin la clave, el contenido ni la ruta.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm

_KEY_HEX_LENGTH: int = 2 * aes_gcm.KEY_SIZE

# Dígitos explícitos: ``bytes.fromhex`` aceptaría espacios entre parejas.
_HEX_DIGITS: frozenset[str] = frozenset("0123456789abcdefABCDEF")

# Avisos de fallo: textos fijos, nunca formateados con datos del usuario.
_MALFORMED_KEY_MESSAGE: str = (
    "La clave está mal formada: deben ser 64 caracteres hexadecimales (0-9, a-f)."
)
_MALFORMED_DATA_MESSAGE: str = (
    "El dato cifrado está mal formado: está vacío o es demasiado corto."
)
_DECRYPT_FAILED_MESSAGE: str = (
    "No se ha podido descifrar: clave incorrecta o dato alterado."
)
_UNENCODABLE_TEXT_MESSAGE: str = (
    "El mensaje contiene caracteres que no se pueden cifrar."
)
_MALFORMED_CIPHERTEXT_MESSAGE: str = (
    "El texto cifrado está mal formado: está vacío, incompleto o tiene caracteres"
    " que no son Base64."
)
_UNDECODABLE_TEXT_MESSAGE: str = (
    "El dato descifrado no es un texto válido."
)

# Tope sobre el fichero original; al descifrar se admiten OVERHEAD bytes más.
MAX_FILE_SIZE: int = 500 * 1024 * 1024

_FILE_TOO_LARGE_MESSAGE: str = (
    f"El fichero supera el tamaño máximo admitido ({MAX_FILE_SIZE // (1024 * 1024)} MiB)."
)
_INPUT_NOT_FOUND_MESSAGE: str = "El fichero de entrada no existe."
_INPUT_UNREADABLE_MESSAGE: str = "No se ha podido leer el fichero de entrada."
_DESTINATION_EXISTS_MESSAGE: str = (
    "El destino ya existe: elige otro. Por seguridad, nunca se sobrescribe un fichero."
)
_WRITE_FAILED_MESSAGE: str = "No se ha podido escribir el fichero de destino."
_WRITE_INCOMPLETE_MESSAGE: str = (
    "No se ha podido escribir el fichero de destino y ha quedado incompleto:"
    " bórralo a mano."
)



def _parse_key(key: str) -> bytes:
    """Convierte la clave hexadecimal (sin espacios en los extremos) en 32 bytes.

    Lanza: DomainError si no son exactamente 64 caracteres ``0-9a-fA-F``.
    """
    text = key.strip()
    if len(text) != _KEY_HEX_LENGTH or not all(char in _HEX_DIGITS for char in text):
        raise DomainError(_MALFORMED_KEY_MESSAGE)
    return bytes.fromhex(text)


def new_session_key() -> str:
    """Genera una clave de sesión nueva: 64 caracteres hexadecimales en minúscula."""
    return aes_gcm.generate_key().hex()


def encrypt_bytes(key: str, plaintext: bytes) -> tuple[bytes, str]:
    """Cifra ``plaintext`` con la clave hexadecimal ``key``.

    Devuelve ``(dato cifrado, nonce_hex)``; el nonce es nuevo en cada llamada.
    Lanza: DomainError si la clave está mal formada.
    Sin tope de tamaño: la librería lanza OverflowError (sin traducir) sobre 2**31 - 1 B.
    """
    raw_key = _parse_key(key)
    data = aes_gcm.encrypt(raw_key, plaintext)
    return data, aes_gcm.nonce_of(data).hex()


def decrypt_bytes(key: str, data: bytes) -> tuple[bytes, str]:
    """Descifra un dato cifrado de :func:`encrypt_bytes`.

    Devuelve ``(contenido, nonce_hex)``.
    Lanza: DomainError si la clave está mal formada, el dato mide menos de 28 B o la
    etiqueta no verifica (aviso común: clave incorrecta o dato alterado).
    """
    raw_key = _parse_key(key)
    # Se comprueba aquí para dar la causa concreta y no incumplir la precondición
    # de ``aes_gcm.decrypt``.
    if len(data) < aes_gcm.OVERHEAD:
        raise DomainError(_MALFORMED_DATA_MESSAGE)
    try:
        plaintext = aes_gcm.decrypt(raw_key, data)
    except aes_gcm.AuthenticationError:
        # La etiqueta no distingue clave incorrecta de dato alterado.
        raise DomainError(_DECRYPT_FAILED_MESSAGE) from None
    return plaintext, aes_gcm.nonce_of(data).hex()


def encrypt_message(key: str, message: str) -> tuple[str, str]:
    """Cifra un mensaje (UTF-8 estricto, sin normalizar) y lo entrega en Base64.

    Devuelve ``(texto cifrado en una línea, nonce_hex)``.
    Lanza: DomainError si el mensaje tiene sustitutos U+D800-U+DFFF (se comprueba
    antes que la clave) o si la clave está mal formada.
    Sin tope: OverflowError de la librería sobre 2**31 - 1 B, sin traducir.
    """
    try:
        plaintext: bytes | None = message.encode("utf-8")
    except UnicodeEncodeError:
        plaintext = None
    # Fuera del ``except``: así el original, que guarda el mensaje, no queda en
    # ``__context__`` del aviso.
    if plaintext is None:
        raise DomainError(_UNENCODABLE_TEXT_MESSAGE)
    data, nonce_hex = encrypt_bytes(key, plaintext)
    # ``b64encode`` no parte en líneas (``encodebytes`` sí) y da ASCII.
    return base64.b64encode(data).decode("ascii"), nonce_hex


def _decode_ciphertext(text: str) -> bytes:
    """Decodifica el Base64 estricto del texto cifrado; no verifica el dato."""
    # strip solo en los extremos; los espacios interiores se rechazan.
    stripped = text.strip()
    if not stripped:
        raise DomainError(_MALFORMED_CIPHERTEXT_MESSAGE)
    try:
        data = base64.b64decode(stripped, validate=True)
    except ValueError:
        # Cubre ``binascii.Error`` y los caracteres no ASCII.
        raise DomainError(_MALFORMED_CIPHERTEXT_MESSAGE) from None
    return data


def decrypt_message(key: str, ciphertext: str) -> tuple[str, str]:
    """Descifra el texto cifrado de :func:`encrypt_message`.

    Devuelve ``(mensaje, nonce_hex)``.
    Lanza: DomainError si el texto no es Base64 válido (se comprueba primero), la
    clave está mal formada, el dato es corto, la etiqueta no verifica o el contenido
    no es UTF-8 válido.
    """
    data = _decode_ciphertext(ciphertext)
    plaintext, nonce_hex = decrypt_bytes(key, data)
    try:
        message: str | None = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        message = None
    # Fuera del ``except``: el original guarda el contenido descifrado y quedaría
    # en ``__context__``.
    if message is None:
        raise DomainError(_UNDECODABLE_TEXT_MESSAGE)
    return message, nonce_hex


def _read_input(source: Path, limit: int) -> bytes:
    """Lee entero ``source``; DomainError si no existe, no se lee o supera ``limit``."""
    try:
        with open(source, "rb") as handle:
            # fstat antes de leer: un fichero grande se rechaza sin leerlo.
            size = os.fstat(handle.fileno()).st_size
            if size > limit:
                too_large = True
            else:
                too_large = False
                data = handle.read()
    except FileNotFoundError:
        raise DomainError(_INPUT_NOT_FOUND_MESSAGE) from None
    except OSError:
        raise DomainError(_INPUT_UNREADABLE_MESSAGE) from None
    # Se vuelve a medir lo leído: el fichero pudo crecer tras el fstat.
    if too_large or len(data) > limit:
        raise DomainError(_FILE_TOO_LARGE_MESSAGE)
    return data


def _write_new(destination: Path, data: bytes) -> None:
    """Crea ``destination`` con ``data`` sin sobrescribir; borra lo creado si falla."""
    try:
        # "xb": apertura exclusiva y atómica, sin carrera entre comprobar y escribir.
        handle = open(destination, "xb")
    except FileExistsError:
        raise DomainError(_DESTINATION_EXISTS_MESSAGE) from None
    except OSError:
        raise DomainError(_WRITE_FAILED_MESSAGE) from None

    write_failed = False
    try:
        with handle:
            handle.write(data)
    except OSError:
        write_failed = True
    if not write_failed:
        return

    # Fuera del except: el aviso no queda encadenado a la excepción original.
    delete_failed = False
    try:
        os.remove(destination)
    except OSError:
        delete_failed = True
    raise DomainError(
        _WRITE_INCOMPLETE_MESSAGE if delete_failed else _WRITE_FAILED_MESSAGE
    )


def encrypt_file(key: str, source: Path, destination: Path) -> str:
    """Cifra ``source`` en un ``destination`` nuevo (original + 28 B). Devuelve el nonce.

    Lanza: DomainError si la clave es inválida, la entrada no existe, no se lee o
    supera ``MAX_FILE_SIZE``, o el destino existe o no se puede escribir.
    """
    _parse_key(key)
    plaintext = _read_input(source, MAX_FILE_SIZE)
    data, nonce_hex = encrypt_bytes(key, plaintext)
    _write_new(destination, data)
    return nonce_hex


def decrypt_file(key: str, source: Path, destination: Path) -> str:
    """Descifra ``source`` en un ``destination`` nuevo. Devuelve el nonce.

    Lanza: DomainError como :func:`encrypt_file`, y además si el dato mide menos de
    28 B o la etiqueta no verifica (entonces no se escribe nada).
    """
    _parse_key(key)
    # Tope = MAX_FILE_SIZE + OVERHEAD: así un original de 500 MiB hace ida y vuelta.
    data = _read_input(source, MAX_FILE_SIZE + aes_gcm.OVERHEAD)
    plaintext, nonce_hex = decrypt_bytes(key, data)
    _write_new(destination, plaintext)
    return nonce_hex
