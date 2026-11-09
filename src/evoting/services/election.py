"""Ciclo completo de una eleccion: preparacion, votacion, cierre y recuento.

Todo mensaje entre entidades pasa por un ``Channel`` cifrado con AES-GCM.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path

from evoting.core import borrell_rifa
from evoting.core.errors import DomainError
from evoting.crypto import randomness
from evoting.services.channel import Channel
from evoting.services.entities import Collector, Counter, Skga, Voter
from evoting.storage import json_files

VOTERS: int = 10
MESA: int = 4
CODES_PER_OPTION: int = 10
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


def create_census(voter_ids: list[str]) -> dict:
    """Censo nuevo: los MESA primeros son la mesa (M1..M4); nadie ha votado."""
    census = {}
    for position, voter_id in enumerate(voter_ids):
        if position < MESA:
            mesa = f"M{position + 1}"
        else:
            mesa = None
        census[voter_id] = {"mesa": mesa, "mark": None}
    return census


def create_vote_codes(size: int = CODES_PER_OPTION) -> dict[str, list[int]]:
    """Administrador: conjuntos publicos C_Si y C_No, con ``size`` valores cada uno.

    Devuelve {"yes": [int], "no": [int]}: valores en [1, P), todos distintos entre si.
    """
    values = []
    while len(values) < 2 * size:
        candidate = randomness.random_below(borrell_rifa.P)
        if candidate != 0 and candidate not in values:
            values.append(candidate)
    return {
        "yes": values[:size],
        "no": values[size:]
    }


def _transmit(channel: Channel, message: dict) -> dict:
    return channel.receive(channel.send(message))


class ElectionService:
    """Ejecuta la eleccion paso a paso; Kb y recibos viven solo en memoria."""

    def __init__(self, data_dir: Path = DEFAULT_DATA_DIR) -> None:
        self._urn_path = data_dir / "urna.json"
        self._census_path = data_dir / "censo.json"
        self._codes_path = data_dir / "codigos.json"
        self._phase = NO_ELECTION
        self._kb = b""  # La Kb que guarda el SKGA hasta entregarla al Recuento.
        self._urn: dict = {}
        self._census: dict = {}
        self._codes: dict = {}
        self._collector: Collector | None = None
        self._voters: dict[str, Voter] = {}

    def prepare(self, voter_ids: list[str] | None = None) -> None:
        """Crea censo, codigos, Kb y urna, y abre la votacion.

        Sin ``voter_ids`` usa V01..V10. Lanza: DomainError si ya hay una eleccion.
        """
        self._require(NO_ELECTION)
        if voter_ids is None:
            voter_ids = [f"V{number:02d}" for number in range(1, VOTERS + 1)]

        # 1. Administrador: censo y codigos publicos.
        census = create_census(voter_ids)
        codes = create_vote_codes()

        # 2. Mesa -> SKGA: aportaciones; el SKGA genera Kb e inicializa la urna.
        skga = Skga()
        contributions = []
        for entry in census.values():
            if entry["mesa"] is not None:
                channel = Channel(entry["mesa"], "SKGA")
                message = _transmit(channel, {"value": randomness.random_bytes(32).hex()})
                contributions.append(bytes.fromhex(message["value"]))
        kb = skga.generate_kb(contributions)
        urn = skga.init_urn(kb, len(voter_ids))

        # 3. SKGA -> Recoleccion: Kb.
        message = _transmit(Channel("SKGA", "Recoleccion"), {"kb": kb.hex()})
        self._collector = Collector(bytes.fromhex(message["kb"]), urn, census)

        self._kb, self._urn, self._census, self._codes = kb, urn, census, codes
        self._voters = {}
        self._publish(self._codes_path, codes)
        self._publish(self._census_path, census)
        self._publish(self._urn_path, urn)
        self._phase = OPEN

    def cast_vote(self, voter_id: str, choice: str) -> None:
        """Paso 4: emite el voto de ``voter_id`` por un canal propio en cada sentido.

        Lanza: DomainError si la votacion no esta abierta o el votante no puede votar.
        """
        self._require(OPEN)
        voter = Voter(voter_id, choice, self._codes)
        to_voter = Channel("Recoleccion", voter_id)
        to_collector = Channel(voter_id, "Recoleccion")
        request = _transmit(to_voter, self._collector.start_vote(voter_id))
        reply = _transmit(to_collector, {"answer": voter.answer(request)})
        self._collector.finish_vote(voter_id, reply["answer"])
        self._voters[voter_id] = voter
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
        message = _transmit(Channel("SKGA", "Recuento"), {"kb": self._kb.hex()})
        result = Counter().count(bytes.fromhex(message["kb"]), self._urn, self._codes)
        self._publish(self._urn_path, self._urn)
        self._phase = COUNTED
        return result

    def verify(self, voter_id: str) -> bool:
        """Paso 7: el votante descarga la urna publica y comprueba su voto.

        Lanza: DomainError si aun no hay recuento, no ha votado o la urna no se puede leer.
        """
        self._require(COUNTED)
        if voter_id not in self._voters:
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
        return tuple(sorted(self._voters))

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
