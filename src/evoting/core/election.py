"""Dominio de la eleccion: censo, urna, fases y permisos de escritura."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from evoting.core.errors import DomainError
from evoting.core.scheme import N_COLUMNS, P, Result

_NOT_AUTHORIZED = "Esta entidad no esta autorizada para realizar el cambio."
_CANNOT_VOTE = "No es posible registrar el voto."
_WRONG_PHASE = "La operacion no es posible en la fase actual de la eleccion."


class Phase(Enum):
    OPEN = "abierta"
    CLOSED = "cerrada"
    COUNTED = "escrutada"


class Role(Enum):
    ADMIN = "administrador"
    SKGA = "skga"
    COLLECTOR = "recolector"
    COUNTER = "escrutador"
    VOTER = "votante"


class Change(Enum):
    PREPARE_CENSUS = "preparar_censo"
    PREPARE_URN = "preparar_urna"
    VOTE = "votar"
    CLOSE = "cerrar"
    COUNT = "recontar"


class Action(Enum):
    PREPARE = "preparar"
    VOTE = "votar"
    CLOSE = "cerrar"
    COUNT = "recontar"
    VERIFY = "verificar"


_ACTIONS: dict[Phase | None, frozenset[Action]] = {
    None: frozenset({Action.PREPARE}),
    Phase.OPEN: frozenset({Action.VOTE, Action.CLOSE}),
    Phase.CLOSED: frozenset({Action.COUNT}),
    Phase.COUNTED: frozenset({Action.VERIFY}),
}


def allowed_actions(phase: Phase | None) -> frozenset[Action]:
    """Acciones que ofrece la interfaz en `phase` (None: sin eleccion preparada)."""
    return _ACTIONS[phase]


_PERMISSIONS: dict[Change, frozenset[Role]] = {
    Change.PREPARE_CENSUS: frozenset({Role.ADMIN}),
    Change.PREPARE_URN: frozenset({Role.SKGA}),
    Change.VOTE: frozenset({Role.COLLECTOR}),
    Change.CLOSE: frozenset({Role.ADMIN}),
    Change.COUNT: frozenset({Role.COUNTER}),
}


def authorize(role: Role, change: Change) -> None:
    """Comprueba que `role` puede aplicar `change`.

    Lanza: DomainError si el rol no esta autorizado.
    """
    if role not in _PERMISSIONS.get(change, frozenset()):
        raise DomainError(_NOT_AUTHORIZED)


@dataclass(frozen=True)
class VoterEntry:
    id: str
    name: str
    table: str | None  # mesa M1..M4 o None
    mark: bytes | None  # marca cifrada de haber votado; None = sin votar


@dataclass(frozen=True)
class Census:
    entries: tuple[VoterEntry, ...]

    def __post_init__(self) -> None:
        ids = [e.id for e in self.entries]
        if len(set(ids)) != len(ids):
            raise DomainError("El censo tiene identificadores repetidos.")

    def require_can_vote(self, voter_id: str) -> None:
        """Comprueba que `voter_id` esta en el censo y no tiene marca.

        Lanza: DomainError si no consta o ya esta marcado.
        """
        for entry in self.entries:
            if entry.id == voter_id:
                if entry.mark is None:
                    return
                break
        raise DomainError(_CANNOT_VOTE)

    def with_mark(self, voter_id: str, data: bytes, *, role: Role) -> Census:
        """Censo nuevo con la marca `data` en `voter_id`; el original no cambia.

        Lanza: DomainError si el rol no puede votar, no consta, ya esta marcado
        o `data` esta vacia.
        """
        authorize(role, Change.VOTE)
        if not isinstance(data, bytes) or not data:
            raise DomainError(_CANNOT_VOTE)
        self.require_can_vote(voter_id)
        return Census(tuple(
            replace(e, mark=bytes(data)) if e.id == voter_id else e for e in self.entries
        ))


@dataclass(frozen=True)
class Urn:
    eid: bytes
    p: int
    c_yes: int
    c_no: int
    phase: Phase
    alphas: tuple[int, ...]
    rows: tuple[tuple[int, ...], ...]
    control: tuple[bytes, ...]
    result: Mapping[str, object] | None

    def __post_init__(self) -> None:
        # Copia de solo lectura: el dict de quien construye no puede mutar la urna.
        if self.result is not None:
            object.__setattr__(self, "result", MappingProxyType(dict(self.result)))

    def with_vote(
        self, row: tuple[int, ...], control: tuple[bytes, ...], *, role: Role
    ) -> Urn:
        """Urna nueva con `row` al final y `control` sustituido; la original no cambia.

        Lanza: DomainError si el rol no puede votar, la fase no es abierta, la fila
        no tiene N_COLUMNS valores en Z_P o el control no tiene N_COLUMNS cifrados.
        """
        authorize(role, Change.VOTE)
        if self.phase is not Phase.OPEN:
            raise DomainError(_CANNOT_VOTE)
        if len(row) != N_COLUMNS or not all(
            isinstance(v, int) and not isinstance(v, bool) and 0 <= v < P for v in row
        ):
            raise DomainError(_CANNOT_VOTE)
        if len(control) != N_COLUMNS or not all(isinstance(c, bytes) and c for c in control):
            raise DomainError(_CANNOT_VOTE)
        return replace(self, rows=(*self.rows, tuple(row)), control=tuple(control))

    def closed(self, *, role: Role) -> Urn:
        """Urna nueva en fase CERRADA.

        Lanza: DomainError si el rol no puede cerrar o la fase no es abierta.
        """
        authorize(role, Change.CLOSE)
        require_phase(self, Phase.OPEN)
        return replace(self, phase=Phase.CLOSED)

    def with_result(self, result: Result, *, role: Role) -> Urn:
        """Urna nueva en fase ESCRUTADA con el resultado publicado.

        Lanza: DomainError si el rol no puede recontar, la fase no es cerrada o
        el resultado no cuadra con sus columnas y los codigos de la urna.
        """
        authorize(role, Change.COUNT)
        require_phase(self, Phase.CLOSED)
        cols = tuple(result.columns)
        if len(cols) != N_COLUMNS or not all(
            isinstance(c, int) and not isinstance(c, bool) and 0 <= c < P for c in cols
        ):
            raise DomainError(_WRONG_PHASE)
        # Los totales se recalculan: un Result hecho a mano no puede falsear el recuento.
        counts = (cols.count(self.c_yes), cols.count(self.c_no), cols.count(0))
        if (result.yes, result.no, result.abstain) != counts or (
            result.null != N_COLUMNS - sum(counts)
        ):
            raise DomainError(_WRONG_PHASE)
        published = {
            "C": tuple(result.columns),
            "si": result.yes,
            "no": result.no,
            "abstencion": result.abstain,
            "nulos": result.null,
        }
        return replace(self, phase=Phase.COUNTED, result=published)


def require_phase(urn: Urn, phase: Phase) -> None:
    """Lanza: DomainError si la urna no esta en la fase `phase`."""
    if urn.phase is not phase:
        raise DomainError(_WRONG_PHASE)


def initial_census() -> Census:
    """Censo V01..V10; V01..V04 con mesa M1..M4 y todas las marcas vacias."""
    entries = tuple(
        VoterEntry(
            id=f"V{i:02d}",
            name=f"Votante {i:02d}",
            table=f"M{i}" if i <= 4 else None,
            mark=None,
        )
        for i in range(1, 11)
    )
    return Census(entries)
