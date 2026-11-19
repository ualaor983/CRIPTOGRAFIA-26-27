"""Canal cifrado entre dos entidades: la clave AES la trae Kyber y los mensajes van con AES-GCM.

Criptografia hibrida (T3 3.8): el emisor encapsula una clave AES-256 nueva con la
clave publica del receptor y le envia la capsula; el receptor la desencapsula con
su clave privada. Cada extremo crea su propio objeto ``Channel``: ninguno recibe la
clave del otro. Por la red viajan la capsula (al abrir) y cada paquete cifrado.

Mensaje: diccionario -> JSON -> AES-GCM. Lleva un numero de secuencia dentro para
rechazar mensajes repetidos o desordenados.
"""

from __future__ import annotations

import json

from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm, kyber


class Channel:
    """Un extremo de un canal en un solo sentido (de ``sender`` a ``receiver``)."""

    def __init__(self, sender: str, receiver: str, key: bytes) -> None:
        self.sender = sender
        self.receiver = receiver
        self._key = key
        self._next_send = 0
        self._next_receive = 0

    @classmethod
    def open_to(
        cls, sender: str, receiver: str, receiver_public_key: bytes
    ) -> tuple[Channel, bytes]:
        """Extremo del emisor: encapsula una clave nueva para el receptor.

        Devuelve el canal y la capsula que hay que enviar al receptor.
        Lanza: DomainError si la clave publica del receptor no es valida.
        """
        try:
            key, capsule = kyber.encapsulate(receiver_public_key)
        except ValueError:
            raise DomainError("La clave publica del receptor no es valida") from None
        return cls(sender, receiver, key), capsule

    @classmethod
    def accept(
        cls, sender: str, receiver: str, receiver_secret_key: bytes, capsule: bytes
    ) -> Channel:
        """Extremo del receptor: desencapsula la clave del canal con su clave privada.

        Lanza: DomainError si la capsula no tiene el formato correcto.
        """
        try:
            key = kyber.decapsulate(receiver_secret_key, capsule)
        except ValueError:
            raise DomainError("La capsula del canal no es valida") from None
        return cls(sender, receiver, key)

    def send(self, message: dict) -> bytes:
        """Cifra ``message`` y devuelve el paquete que viaja por la red."""
        numbered = {**message, "seq": self._next_send}
        plain = json.dumps(numbered).encode("utf-8")
        cipher = aes_gcm.encrypt(self._key, plain)
        self._next_send += 1
        return cipher

    def receive(self, packet: bytes) -> dict:
        """Descifra un paquete y devuelve el mensaje (sin "seq").

        Lanza: DomainError si el paquete esta alterado, la clave no es la del emisor
        (capsula alterada o dirigida a otro) o su "seq" no es el esperado.
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
