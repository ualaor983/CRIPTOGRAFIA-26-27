"""Canales cifrados entre entidades y registro de trafico en memoria.

Cada enlace usa una clave AES nueva; el registro solo guarda tramas cifradas en hex.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm, randomness
from evoting.crypto.channel import ChannelError, SecureChannel

_CLOSED_MESSAGE = "El canal está cerrado."
_UNKNOWN_PARTY_MESSAGE = "La entidad no pertenece al canal."
_REJECTED_MESSAGE = "Mensaje rechazado por el canal."
_MALFORMED_MESSAGE = "Mensaje del canal mal formado."
_UNSERIALIZABLE_MESSAGE = "El mensaje no se puede enviar por el canal."


@dataclass(frozen=True)
class TrafficEntry:
    """Una trama observada en la red: canal, origen, destino y trama cifrada en hex."""

    channel: str
    sender: str
    receiver: str
    frame_hex: str

    @property
    def frame_preview(self) -> str:
        """Primeros 32 caracteres hex de la trama, con puntos suspensivos si se corta."""
        return self.frame_hex if len(self.frame_hex) <= 32 else self.frame_hex[:32] + "..."


class Link:
    """Enlace cifrado entre dos entidades; un extremo por parte, misma clave."""

    def __init__(self, hub: ChannelHub, name: str, a: str, b: str) -> None:
        channel_id = f"{name}#{randomness.random_bytes(8).hex()}"
        key = aes_gcm.generate_key()
        self._hub = hub
        self._name = name
        self._ends = {
            a: SecureChannel(channel_id, key, "a"),
            b: SecureChannel(channel_id, key, "b"),
        }
        self._peer = {a: b, b: a}
        self._closed = False

    @property
    def name(self) -> str:
        return self._name

    def send(self, sender: str, message: dict) -> bytes:
        """Cifra ``message``, lo registra y devuelve la trama tras ``deliver``.

        Lanza: DomainError si el enlace esta cerrado, la entidad no es del canal o el
        mensaje no es serializable.
        """
        self._check(sender)
        try:
            raw = json.dumps(message, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            raise DomainError(_UNSERIALIZABLE_MESSAGE) from None
        receiver = self._peer[sender]
        try:
            frame = self._ends[sender].seal(raw)
        except ChannelError:
            raise DomainError(_REJECTED_MESSAGE) from None
        self._hub._record(TrafficEntry(self._name, sender, receiver, frame.hex()))
        return self._hub.deliver(frame)

    def receive(self, receiver: str, frame: bytes) -> dict:
        """Verifica y descifra ``frame`` en el extremo ``receiver``.

        Lanza: DomainError si el enlace esta cerrado, la trama no es autentica o esta
        fuera de secuencia, o el contenido no es un objeto JSON.
        """
        self._check(receiver)
        if not isinstance(frame, bytes):
            raise DomainError(_REJECTED_MESSAGE)
        try:
            raw = self._ends[receiver].open(frame)
        except (ChannelError, aes_gcm.AuthenticationError):
            raise DomainError(_REJECTED_MESSAGE) from None
        try:
            message = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            raise DomainError(_MALFORMED_MESSAGE) from None
        if not isinstance(message, dict):
            raise DomainError(_MALFORMED_MESSAGE)
        return message

    def close(self) -> None:
        """Cierra el enlace y descarta sus claves."""
        self._closed = True
        for end in self._ends.values():
            end.close()
        self._ends = {}

    def _check(self, party: str) -> None:
        if self._closed:
            raise DomainError(_CLOSED_MESSAGE)
        if party not in self._ends:
            raise DomainError(_UNKNOWN_PARTY_MESSAGE)


class ChannelHub:
    """Crea enlaces y guarda el registro de trafico (solo tramas cifradas)."""

    def __init__(self) -> None:
        self._traffic: list[TrafficEntry] = []
        # Punto de red entre emisor y receptor; un script puede sustituirlo.
        self.deliver: Callable[[bytes], bytes] = lambda frame: frame

    def open(self, name: str, a: str, b: str) -> Link:
        """Abre un enlace ``a``-``b`` con clave nueva. Lanza: DomainError si a == b."""
        if a == b:
            raise DomainError(_UNKNOWN_PARTY_MESSAGE)
        return Link(self, name, a, b)

    def traffic(self) -> tuple[TrafficEntry, ...]:
        """Devuelve las tramas registradas hasta ahora (crece hasta ``reset``)."""
        return tuple(self._traffic)

    def reset(self) -> None:
        """Vacia el registro de trafico."""
        self._traffic.clear()

    def _record(self, entry: TrafficEntry) -> None:
        self._traffic.append(entry)
