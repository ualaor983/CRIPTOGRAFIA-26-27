"""Fachada de la eleccion: prepara censo y urna y los persiste como version publica."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from evoting.core import election, scheme
from evoting.core.errors import DomainError
from evoting.services.channels import ChannelHub, TrafficEntry
from evoting.services.entities import (
    Administrator,
    Collector,
    Counter,
    Receipt,
    Skga,
    Voter,
    package_from_message,
    package_to_message,
)
from evoting.storage import json_store

# Reexportados para que ui solo dependa de services.
Action = election.Action
Option = scheme.Option

DEFAULT_DATA_DIR = Path("data") / "elecciones"


def _result_to_json(result: Mapping[str, object]) -> dict[str, object]:
    out = dict(result)
    out["C"] = [str(c) for c in result["C"]]
    return out


def urn_to_json(urn: election.Urn) -> dict[str, object]:
    """Urna como JSON publico: enteros en decimal, cifrados en hex."""
    return {
        "eleccion": urn.eid.hex(),
        "p": str(urn.p),
        "c_si": str(urn.c_yes),
        "c_no": str(urn.c_no),
        "fase": urn.phase.value,
        "alfas": [str(a) for a in urn.alphas],
        "votos": [[str(x) for x in row] for row in urn.rows],
        "control": [c.hex() for c in urn.control],
        "resultado": None if urn.result is None else _result_to_json(urn.result),
    }


def census_to_json(census: election.Census) -> list[dict[str, object]]:
    """Censo como JSON publico; `estado` vacio si el votante no ha votado."""
    return [
        {
            "id": e.id,
            "nombre": e.name,
            "mesa": e.table,
            "estado": "" if e.mark is None else e.mark.hex(),
        }
        for e in census.entries
    ]


_BAD_STORE = "La version vigente no es legible."


def urn_from_json(data: dict) -> election.Urn:
    """Inversa de `urn_to_json`. Lanza: DomainError si el JSON no tiene esa forma."""
    try:
        return election.Urn(
            eid=bytes.fromhex(data["eleccion"]),
            p=int(data["p"]),
            c_yes=int(data["c_si"]),
            c_no=int(data["c_no"]),
            phase=election.Phase(data["fase"]),
            alphas=tuple(int(a) for a in data["alfas"]),
            rows=tuple(tuple(int(x) for x in row) for row in data["votos"]),
            control=tuple(bytes.fromhex(c) for c in data["control"]),
            result=data["resultado"],
        )
    except (KeyError, TypeError, ValueError):
        raise DomainError(_BAD_STORE) from None


def _check_urn(urn: election.Urn, eid: str) -> None:
    """Valida la urna leida de disco antes de usarla. Lanza: DomainError si no cuadra."""
    def is_elem(v: object, low: int) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and low <= v < scheme.P

    ok = (
        urn.p == scheme.P
        and urn.eid.hex() == eid
        and is_elem(urn.c_yes, 1) and is_elem(urn.c_no, 1) and urn.c_yes != urn.c_no
        and len(urn.alphas) == scheme.N_COLUMNS
        and len(set(urn.alphas)) == scheme.N_COLUMNS
        and all(is_elem(a, 1) for a in urn.alphas)
        and all(len(r) == scheme.N_COLUMNS and all(is_elem(x, 0) for x in r)
                for r in urn.rows)
        and len(urn.control) == scheme.N_COLUMNS
        and all(c for c in urn.control)
        and (urn.result is None) == (urn.phase is not election.Phase.COUNTED)
    )
    if not ok:
        raise DomainError(_BAD_STORE)


def census_from_json(data: list) -> election.Census:
    """Inversa de `census_to_json`. Lanza: DomainError si el JSON no tiene esa forma."""
    try:
        return election.Census(tuple(
            election.VoterEntry(
                e["id"], e["nombre"], e["mesa"],
                bytes.fromhex(e["estado"]) if e["estado"] else None,
            )
            for e in data
        ))
    except (KeyError, TypeError, ValueError):
        raise DomainError(_BAD_STORE) from None


@dataclass(frozen=True)
class Verification:
    """Resultado de `verify`: fila hallada, su indice y si su opcion fue contada."""

    found: bool
    index: int | None
    counted: bool | None  # None: aun no hay resultado publicado


def _short_hex(data: bytes, shown: int = 16) -> str:
    """Hex abreviado para mostrar: primeros `shown` caracteres y longitud en bytes."""
    text = data.hex()
    return f"{text[:shown]}… ({len(data)} B)" if len(text) > shown else text


@dataclass(frozen=True)
class CensusRow:
    """Fila publica del censo; `mark_hex` vacio si no ha votado."""

    id: str
    name: str
    table: str
    mark_hex: str


@dataclass(frozen=True)
class ResultView:
    """Resultado publicado, todo en texto."""

    columns: tuple[str, ...]
    yes: str
    no: str
    abstain: str
    null: str


@dataclass(frozen=True)
class ElectionSnapshot:
    """Vista publica lista para mostrar: nunca Kb, claves de canal ni recibos."""

    phase: str
    p: str
    c_yes: str
    c_no: str
    alphas: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    control_hex: tuple[str, ...]
    census: tuple[CensusRow, ...]
    result: ResultView | None


class ElectionService:
    """Orquesta las entidades; Kb vive solo en memoria (SKGA y Recoleccion)."""

    def __init__(self, data_dir: Path = DEFAULT_DATA_DIR) -> None:
        self._data_dir = Path(data_dir)
        self._skga: Skga | None = None
        self._collector: Collector | None = None
        self._receipts: dict[str, Receipt] = {}
        self._eid: str | None = None
        self._hub = ChannelHub()

    def traffic(self) -> tuple[TrafficEntry, ...]:
        """Tramas cifradas observadas en la red desde la ultima preparacion."""
        return self._hub.traffic()

    def prepare(self) -> dict[str, object]:
        """Prepara una eleccion nueva (version 1) y devuelve su `snapshot()`.

        Lanza: DomainError si ya hay una eleccion preparada o falla el almacen.
        """
        if self._skga is not None:
            raise DomainError("Ya hay una eleccion preparada en este servicio.")
        election.authorize(election.Role.ADMIN, election.Change.PREPARE_CENSUS)
        self._hub.reset()
        package = Administrator().prepare()
        link = self._hub.open("admin->skga", "admin", "skga")
        try:
            frame = link.send("admin", package_to_message(package))
            package = package_from_message(link.receive("skga", frame))
        finally:
            link.close()
        skga = Skga()
        urn = skga.prepare(package)
        link = self._hub.open("skga->collector", "skga", "collector")
        try:
            frame = link.send("skga", skga.key_message())
            collector = Collector.from_key_message(link.receive("collector", frame))
        finally:
            link.close()
        self._commit(
            election.Role.SKGA, election.Change.PREPARE_URN, urn, package.census
        )
        self._skga = skga
        self._collector = collector
        self._receipts = {}
        self._eid = urn.eid.hex()
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        """Version vigente leida del disco: solo datos publicos, nunca Kb.

        Lanza: DomainError si no hay eleccion preparada.
        """
        if self._eid is None:
            raise DomainError("No hay eleccion preparada.")
        version, files = json_store.read_current(self._data_dir / self._eid)
        return {"version": version, **files}

    def view(self) -> ElectionSnapshot:
        """Vista publica de la version vigente (para la UI); no incluye recibos.

        Lanza: DomainError si no hay eleccion preparada o la version no es legible.
        """
        _, urn, census = self._load()
        result = None
        if urn.result is not None:
            try:
                result = ResultView(
                    tuple(str(c) for c in urn.result["C"]),
                    str(urn.result["si"]), str(urn.result["no"]),
                    str(urn.result["abstencion"]), str(urn.result["nulos"]),
                )
            except KeyError:
                raise DomainError(_BAD_STORE) from None
        return ElectionSnapshot(
            phase=urn.phase.value,
            p=str(urn.p),
            c_yes=str(urn.c_yes),
            c_no=str(urn.c_no),
            alphas=tuple(str(a) for a in urn.alphas),
            rows=tuple(tuple(str(x) for x in row) for row in urn.rows),
            control_hex=tuple(_short_hex(c) for c in urn.control),
            census=tuple(
                CensusRow(e.id, e.name, e.table or "",
                          "" if e.mark is None else _short_hex(e.mark))
                for e in census.entries
            ),
            result=result,
        )

    def allowed_actions(self) -> frozenset[election.Action]:
        """Acciones habilitadas segun la fase vigente (solo PREPARE sin eleccion)."""
        if self._eid is None:
            return election.allowed_actions(None)
        return election.allowed_actions(self._load()[1].phase)

    def voter_ids(self) -> tuple[str, ...]:
        """Identificadores del censo vigente.

        Lanza: DomainError si no hay eleccion preparada.
        """
        return tuple(e.id for e in self._load()[2].entries)

    def receipt_ids(self) -> tuple[str, ...]:
        """Votantes que tienen recibo en este servicio (no revela su contenido)."""
        return tuple(sorted(self._receipts))

    def receipt(self, voter_id: str) -> Receipt:
        """Recibo del propio votante (la UI lo limita).

        Lanza: DomainError si no ha votado aqui.
        """
        try:
            return self._receipts[voter_id]
        except KeyError:
            raise DomainError("No hay recibo para ese votante.") from None

    def cast_vote(self, voter_id: str, option: scheme.Option) -> Receipt:
        """Emite el voto de `voter_id` por un canal de sesion nuevo; devuelve su recibo.

        Urna, control y censo se confirman en una sola version nueva.
        Lanza: DomainError si no hay eleccion, el votante no puede votar o la sesion falla.
        """
        if self._eid is None or self._collector is None:
            raise DomainError("No hay eleccion preparada.")
        collector = self._collector
        root = self._data_dir / self._eid
        version, files = json_store.read_current(root)
        urn = urn_from_json(files["urna.json"])
        _check_urn(urn, self._eid)
        census = census_from_json(files["censo.json"])
        voter = Voter(voter_id, urn.c_yes, urn.c_no, urn.alphas)
        link = self._hub.open(f"voter:{voter_id}", "voter", "collector")
        try:
            frame = link.send("voter", voter.request())
            request = link.receive("collector", frame)
            message, offer = collector.offer(request, urn, census)
            frame = link.send("collector", message)
            reply, receipt = voter.respond(link.receive("voter", frame), option)
            frame = link.send("voter", reply)
            new_urn, new_census = collector.accept(
                offer, link.receive("collector", frame), urn, census
            )
            self._commit(
                election.Role.COLLECTOR, election.Change.VOTE, new_urn, new_census,
                version + 1,
            )
        finally:
            link.close()
        self._receipts[voter_id] = receipt
        return receipt

    def close(self) -> None:
        """El Administrador cierra la votacion (fase cerrada) en una version nueva.

        Lanza: DomainError si no hay eleccion o la fase no es abierta.
        """
        version, urn, census = self._load()
        new_urn = urn.closed(role=election.Role.ADMIN)
        self._commit(
            election.Role.ADMIN, election.Change.CLOSE, new_urn, census, version + 1
        )

    def count(self) -> dict[str, object]:
        """Recuento: Kb pasa de SKGA al Recuento por un canal nuevo y se publica C.

        Devuelve el `snapshot()` con el resultado. Kb no se escribe en ningun sitio.
        Lanza: DomainError si la fase no es cerrada o algo no autentica (nada se escribe).
        """
        version, urn, census = self._load()
        election.require_phase(urn, election.Phase.CLOSED)
        if self._skga is None:
            raise DomainError("No hay eleccion preparada.")
        link = self._hub.open("skga->counter", "skga", "counter")
        try:
            frame = link.send("skga", self._skga.key_message())
            new_urn = Counter().count(link.receive("counter", frame), urn, census)
        finally:
            link.close()
        self._commit(
            election.Role.COUNTER, election.Change.COUNT, new_urn, census, version + 1
        )
        return self.snapshot()

    def verify(self, voter_id: str) -> Verification:
        """Verificacion individual con el recibo propio y la urna publica (sin Kb).

        Relee el disco, localiza la fila del votante y, si ya hay resultado,
        comprueba que C[h_t] es su codigo. `counted` es None sin resultado.
        Lanza: DomainError si no hay recibo, eleccion, o la version no es legible.
        """
        receipt = self.receipt(voter_id)
        _, urn, _ = self._load()
        index = scheme.find_row(
            urn.rows, urn.alphas, receipt.coeffs, receipt.h_t, receipt.code
        )
        counted: bool | None = None
        if urn.result is not None:
            try:
                counted = int(urn.result["C"][receipt.h_t - 1]) == receipt.code
            except (KeyError, IndexError, TypeError, ValueError):
                raise DomainError(_BAD_STORE) from None
        return Verification(index is not None, index, counted)

    def _load(self) -> tuple[int, election.Urn, election.Census]:
        if self._eid is None:
            raise DomainError("No hay eleccion preparada.")
        version, files = json_store.read_current(self._data_dir / self._eid)
        urn = urn_from_json(files["urna.json"])
        _check_urn(urn, self._eid)
        return version, urn, census_from_json(files["censo.json"])

    def _commit(
        self,
        role: election.Role,
        change: election.Change,
        urn: election.Urn,
        census: election.Census,
        version: int = 1,
    ) -> None:
        # Limitacion: roles fijos en el codigo; no se autentica a las entidades.
        election.authorize(role, change)
        json_store.write_version(
            self._data_dir / urn.eid.hex(),
            version,
            {"urna.json": urn_to_json(urn), "censo.json": census_to_json(census)},
        )
