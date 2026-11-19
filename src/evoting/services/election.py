"""Ciclo completo de una eleccion: preparacion, votacion, cierre y recuento.

Todo mensaje entre entidades pasa por un ``Channel`` cifrado con AES-GCM cuya
clave transmite Kyber. Al preparar, el Administrador (Entidad Certificadora) da
a cada participante su par de claves Kyber y publica las claves publicas en el
directorio; el emisor de cada comunicacion toma de ahi la clave del receptor.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path

from evoting.core import borrell_rifa
from evoting.core.errors import DomainError
from evoting.crypto import randomness
from evoting.services.channel import Channel
from evoting.services.entities import (
    Administrator,
    Collector,
    Counter,
    Participant,
    Skga,
    Voter,
)
from evoting.storage import json_files

VOTERS: int = 10
MESA: int = 4
CODES_PER_OPTION: int = 10
# p tiene 128 bits: todo valor de Z_p cabe en los 16 B de una celda cifrada (sealing).
PRIME_BITS: int = 128
DEFAULT_DATA_DIR: Path = Path("data")

NO_ELECTION: str = ""
OPEN: str = "abierta"
CLOSED: str = "cerrada"
COUNTED: str = "escrutada"


class Action(Enum):
    """Lo que la ventana puede ofrecer en cada fase."""

    PREPARE = "preparar"
    VOTE = "votar"
    CLOSE = "cerrar"
    COUNT = "recontar"
    VERIFY = "verificar"


class Option(StrEnum):
    """Opciones de voto que ofrece la ventana."""

    YES = borrell_rifa.YES
    NO = borrell_rifa.NO
    ABSTAIN = borrell_rifa.ABSTENTION


_ACTIONS: dict[str, frozenset[Action]] = {
    NO_ELECTION: frozenset({Action.PREPARE}),
    OPEN: frozenset({Action.VOTE, Action.CLOSE}),
    CLOSED: frozenset({Action.COUNT}),
    COUNTED: frozenset({Action.VERIFY}),
}


@dataclass(frozen=True)
class CensusRow:
    """Fila publica del censo, en texto; ``mark_hex`` vacio si no ha votado."""

    id: str
    name: str
    table: str
    mark_hex: str


@dataclass(frozen=True)
class ResultView:
    """Recuento publicado, en texto."""

    yes: str
    no: str
    abstain: str
    null: str


@dataclass(frozen=True)
class ElectionSnapshot:
    """Vista publica lista para mostrar: nunca Kb, claves de canal ni recibos."""

    phase: str
    alphas: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    control_hex: tuple[str, ...]
    census: tuple[CensusRow, ...]
    result: ResultView | None


def _transmit(
    sender: str, receiver: Participant, directory: dict[str, str], message: dict
) -> dict:
    """Una comunicacion de ``sender`` a ``receiver`` con una clave AES nueva traida por Kyber.

    Lanza: DomainError si el paquete o la capsula no son validos.
    """
    # Emisor: busca la clave publica del receptor y encapsula una clave AES nueva.
    receiver_public_key = bytes.fromhex(directory[receiver.name])
    channel, capsule = Channel.open_to(sender, receiver.name, receiver_public_key)
    packet = channel.send(message)
    # Por la red viajan la capsula y el paquete.
    # Receptor: desencapsula la clave con su clave privada y descifra.
    return receiver.accept(sender, capsule).receive(packet)


class ElectionService:
    """Ejecuta la eleccion paso a paso; Kb y recibos viven solo en memoria."""

    def __init__(self, data_dir: Path = DEFAULT_DATA_DIR) -> None:
        self._urn_path = data_dir / "urna.json"
        self._census_path = data_dir / "censo.json"
        self._codes_path = data_dir / "codigos.json"
        self._directory_path = data_dir / "directorio.json"
        self._phase = NO_ELECTION
        self._kb = b""  # La Kb que guarda el SKGA hasta entregarla al Recuento.
        self._urn: dict = {}
        self._census: dict = {}
        self._codes: dict = {}
        self._directory: dict[str, str] = {}  # Claves publicas: lo que publica la CA.
        self._admin: Administrator | None = None  # Guarda su propio par y el directorio.
        self._skga = Skga()
        self._collector = Collector()
        self._counter = Counter()
        self._voters: dict[str, Voter] = {}

    def prepare(self, voter_ids: list[str] | None = None) -> None:
        """Crea p, censo, codigos, pares de claves, Kb y urna, y abre la votacion.

        Sin ``voter_ids`` usa V01..V10. Lanza: DomainError si ya hay una eleccion.
        """
        self._require(NO_ELECTION)
        if voter_ids is None:
            voter_ids = [f"V{number:02d}" for number in range(1, VOTERS + 1)]

        # 1. Administrador: primo p nuevo en cada eleccion, censo y codigos publicos.
        admin = Administrator()
        p = admin.generate_prime(PRIME_BITS)
        census = admin.create_census(voter_ids, MESA)
        codes = admin.create_vote_codes(p, CODES_PER_OPTION)

        # 2. Administrador como Entidad Certificadora: crea el par de cada participante,
        #    se lo entrega y publica su clave publica. No guarda ninguna clave privada.
        skga, collector, counter = Skga(), Collector(), Counter()
        voters = {voter_id: Voter(voter_id, codes) for voter_id in voter_ids}
        for participant in [skga, collector, counter, *voters.values()]:
            admin.issue_keys(participant)

        # 3. Mesa -> SKGA: aportaciones; el SKGA genera Kb e inicializa la urna.
        contributions = []
        for entry in census.values():
            if entry["mesa"] is not None:
                value = randomness.random_bytes(32).hex()
                message = _transmit(entry["mesa"], skga, admin.directory, {"value": value})
                contributions.append(bytes.fromhex(message["value"]))
        kb = skga.generate_kb(contributions)
        urn = skga.init_urn(kb, len(voter_ids), p)

        # 4. SKGA -> Recoleccion: Kb.
        message = _transmit(skga.name, collector, admin.directory, {"kb": kb.hex()})
        collector.prepare(bytes.fromhex(message["kb"]), urn, census, p)

        self._kb, self._urn, self._census, self._codes = kb, urn, census, codes
        self._admin, self._skga, self._collector, self._counter = admin, skga, collector, counter
        self._voters = voters
        self._directory = admin.directory
        self._publish(self._directory_path, self._directory)
        self._publish(self._codes_path, codes)
        self._publish(self._census_path, census)
        self._publish(self._urn_path, urn)
        self._phase = OPEN

    def cast_vote(self, voter_id: str, choice: str) -> None:
        """Paso 4: emite el voto de ``voter_id``; cada sentido con su propia clave Kyber.

        Lanza: DomainError si la votacion no esta abierta o el votante no puede votar.
        """
        self._require(OPEN)
        offer = self._collector.start_vote(voter_id)  # comprueba antes el censo
        voter = self._voters[voter_id]
        collector = self._collector
        request = _transmit(collector.name, voter, self._directory, offer)
        answer = voter.answer(request, choice)
        reply = _transmit(voter_id, collector, self._directory, {"answer": answer})
        collector.finish_vote(voter_id, reply["answer"])
        self._publish(self._urn_path, self._urn)
        self._publish(self._census_path, self._census)

    def close(self) -> None:
        """Paso 5: cierra la votacion. Lanza: DomainError si no esta abierta."""
        self._require(OPEN)
        self._phase = CLOSED

    def count(self) -> list[str]:
        """Paso 6: SKGA -> Recuento: Kb; recuenta, publica y devuelve cada columna.

        Lanza: DomainError si no esta cerrada o el control esta alterado.
        """
        self._require(CLOSED)
        message = _transmit(self._skga.name, self._counter, self._directory, {"kb": self._kb.hex()})
        result = self._counter.count(bytes.fromhex(message["kb"]), self._urn, self._codes)
        self._publish(self._urn_path, self._urn)
        self._phase = COUNTED
        return result

    def verify(self, voter_id: str) -> bool:
        """Paso 7: el votante descarga la urna publica y comprueba su voto.

        Lanza: DomainError si aun no hay recuento, no ha votado o la urna no se puede leer.
        """
        self._require(COUNTED)
        if voter_id not in self._voters or self._voters[voter_id].receipt is None:
            raise DomainError("Ese votante no tiene recibo.")
        try:
            return self._voters[voter_id].verify(json_files.load(self._urn_path))
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            raise DomainError("La urna publicada no se puede leer.") from None

    def allowed_actions(self) -> frozenset[Action]:
        """Acciones disponibles en la fase actual."""
        return _ACTIONS[self._phase]

    def voter_ids(self) -> tuple[str, ...]:
        """Identificadores del censo."""
        return tuple(self._census)

    def receipt_ids(self) -> tuple[str, ...]:
        """Votantes que han votado y pueden verificar."""
        return tuple(
            sorted(voter_id for voter_id, voter in self._voters.items() if voter.receipt)
        )

    def view(self) -> ElectionSnapshot:
        """Vista publica de la eleccion. Lanza: DomainError si no hay eleccion."""
        if self._phase == NO_ELECTION:
            raise DomainError("No hay eleccion preparada.")
        census = tuple(
            CensusRow(
                voter_id,
                f"Votante {voter_id[1:]}",
                entry["mesa"] or "",
                entry["mark"] or "",
            )
            for voter_id, entry in self._census.items()
        )
        result = None
        if self._urn["result"] is not None:
            counts = self._urn["result"]
            result = ResultView(
                str(counts.count(borrell_rifa.YES)),
                str(counts.count(borrell_rifa.NO)),
                str(counts.count(borrell_rifa.ABSTENTION)),
                str(counts.count(borrell_rifa.NULL)),
            )
        return ElectionSnapshot(
            self._phase,
            tuple(str(alpha) for alpha in self._urn["alphas"]),
            tuple(tuple(str(cell) for cell in row) for row in self._urn["votes"]),
            tuple(self._urn["control"]),
            census,
            result,
        )

    def _require(self, phase: str) -> None:
        if self._phase != phase:
            raise DomainError("Esa accion no esta disponible en la fase actual.")

    @staticmethod
    def _publish(path: Path, data: dict) -> None:
        try:
            json_files.save(path, data)
        except OSError:
            raise DomainError(f"No se ha podido guardar {path.name}.") from None


def run_election(choices: dict[str, str], data_dir: Path) -> list[str]:
    """Ejecuta la eleccion con el voto de cada votante y devuelve el resultado por columna.

    ``choices``: {"V01": "si", "V02": "no", ...}. Guarda urna, censo y codigos en data_dir.
    """
    service = ElectionService(data_dir)
    service.prepare(list(choices))
    for voter_id, choice in choices.items():
        service.cast_vote(voter_id, choice)
    service.close()
    result = service.count()
    if not all(service.verify(voter_id) for voter_id in choices):
        raise DomainError("Un votante no ha podido verificar su voto.")
    return result
