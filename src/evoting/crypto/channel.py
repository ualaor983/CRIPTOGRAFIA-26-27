"""Canal autenticado sobre AES-256-GCM: liga cada trama a canal, sentido y secuencia.

Trama: ``seq (8 B big-endian) || nonce (12 B) || cifrado (n B) || etiqueta (16 B)``.
Solo reutiliza ``aes_gcm``; el receptor exige la secuencia esperada de cada sentido.
"""

from __future__ import annotations

from evoting.crypto import aes_gcm

SEQ_SIZE: int = 8

# Tamaño mínimo de una trama válida (secuencia, nonce y etiqueta).
FRAME_OVERHEAD: int = SEQ_SIZE + aes_gcm.OVERHEAD

_MAX_SEQ: int = 2**64 - 1


class ChannelError(Exception):
    """Trama mal formada, fuera de secuencia (reenvío o reordenación) o canal agotado."""


class SecureChannel:
    """Un extremo ("a" o "b") de un canal con clave compartida; un contador por sentido.

    No es seguro entre hilos: la entrega es sincrona en un solo proceso.
    """

    def __init__(self, channel_id: str, key: bytes, role: str) -> None:
        """AES-256-GCM, clave 32 B, nonce 12 B nuevo por trama (lo genera ``aes_gcm``).

        ``channel_id`` identifica el canal y entra en el AAD; ``role`` fija el sentido
        de envio (``a>b`` o ``b>a``) y el de recepcion es el contrario.
        Lanza: ValueError si ``key`` no son 32 bytes, ``role`` no es "a"/"b".
        """
        if not isinstance(key, bytes) or len(key) != aes_gcm.KEY_SIZE:
            raise ValueError(f"La clave debe medir exactamente {aes_gcm.KEY_SIZE} bytes.")
        if role not in ("a", "b"):
            raise ValueError("El rol debe ser 'a' o 'b'.")
        self._channel_id = channel_id
        self._key: bytes | None = key
        self._send_dir = "a>b" if role == "a" else "b>a"
        self._recv_dir = "b>a" if role == "a" else "a>b"
        self._send_seq = 0
        self._recv_seq = 0

    def close(self) -> None:
        """Descarta la clave; despues seal y open lanzan ChannelError."""
        self._key = None

    def seal(self, plaintext: bytes) -> bytes:
        """Cifra ``plaintext`` en el sentido de envio y avanza su secuencia.

        Lanza: ChannelError si el canal esta cerrado o se agoto la secuencia.
        """
        if self._key is None:
            raise ChannelError("Canal cerrado.")
        seq = self._send_seq
        if seq > _MAX_SEQ:
            raise ChannelError("Canal agotado.")
        header = seq.to_bytes(SEQ_SIZE, "big")
        data = aes_gcm.encrypt(self._key, plaintext, aad=self._aad(self._send_dir, header))
        self._send_seq = seq + 1
        return header + data

    def open(self, frame: bytes) -> bytes:
        """Verifica y descifra una trama del sentido de recepcion; avanza solo si es valida.

        Lanza: ChannelError si el canal esta cerrado, la trama es corta o su secuencia
        no es la esperada; AuthenticationError (de ``aes_gcm``) si la etiqueta no
        verifica (alterada, otra clave, otro canal u otro sentido).
        """
        if self._key is None:
            raise ChannelError("Canal cerrado.")
        if len(frame) < FRAME_OVERHEAD:
            raise ChannelError("Trama demasiado corta.")
        header = frame[:SEQ_SIZE]
        # Primero la etiqueta: asi una secuencia alterada se rechaza como alteracion
        # y solo una trama autentica puede dar "fuera de secuencia".
        plaintext = aes_gcm.decrypt(
            self._key, frame[SEQ_SIZE:], aad=self._aad(self._recv_dir, header)
        )
        if int.from_bytes(header, "big") != self._recv_seq:
            raise ChannelError("Trama fuera de secuencia.")
        self._recv_seq += 1
        return plaintext

    def _aad(self, direction: str, header: bytes) -> bytes:
        # Campos con prefijo de longitud: sin colisiones entre canal y sentido.
        out = _field(b"evoting/1") + _field(b"channel")
        for raw in (self._channel_id.encode("utf-8"), direction.encode("utf-8"), header):
            out += _field(raw)
        return out


def _field(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw
