"""Canal cifrado entre dos entidades con una clave de sesion AES-256-GCM propia.

Mensaje: diccionario -> JSON -> AES-GCM. Lleva un numero de secuencia dentro para
rechazar mensajes repetidos o desordenados.
"""

from __future__ import annotations

import json

from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm


class Channel:
    """Canal en un solo sentido (de ``sender`` a ``receiver``) con su clave de sesion."""

    def __init__(self, sender: str, receiver: str) -> None:
        self.sender = sender
        self.receiver = receiver
        self._key = aes_gcm.generate_key()
        self._next_send = 0
        self._next_receive = 0

    def send(self, message: dict) -> bytes:
        """Cifra ``message`` y devuelve el paquete que viaja por la red."""
        numbered = {**message, "seq": self._next_send}
        plain = json.dumps(numbered).encode("utf-8")
        cipher = aes_gcm.encrypt(self._key, plain)
        self._next_send += 1
        return cipher

    def receive(self, packet: bytes) -> dict:
        """Descifra un paquete y devuelve el mensaje (sin "seq").

        Lanza: DomainError si el paquete esta alterado o su "seq" no es el esperado.
        """
        try:
            plain = aes_gcm.decrypt(self._key, packet)
            message = json.loads(plain.decode("utf-8"))
            seq = message.pop("seq")
            if seq != self._next_receive:
                raise DomainError("Mensaje repetido o fuera de orden")
            self._next_receive += 1
            return message
        except (
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            aes_gcm.AuthenticationError,
        ):
            raise DomainError("El paquete esta alterado o la clave incorrecta") from None
