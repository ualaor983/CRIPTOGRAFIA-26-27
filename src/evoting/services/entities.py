"""Entidades del esquema: Administrador, SKGA (Kb, alfas), Recoleccion, Recuento, votante."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from evoting.core import election, scheme
from evoting.core.errors import DomainError
from evoting.crypto import aes_gcm, randomness
from evoting.services import sealing


@dataclass(frozen=True)
class AdminPackage:
    """Lo que el Administrador entrega a la SKGA: censo y codigos C_Si, C_No."""

    census: election.Census
    c_yes: int
    c_no: int


_BAD_PACKAGE = "Paquete de la eleccion mal formado."


def package_to_message(package: AdminPackage) -> dict[str, object]:
    """Paquete del Administrador como mensaje JSON: enteros en decimal, marcas en hex."""
    return {
        "censo": [
            {
                "id": e.id,
                "nombre": e.name,
                "mesa": e.table,
                "estado": "" if e.mark is None else e.mark.hex(),
            }
            for e in package.census.entries
        ],
        "c_si": str(package.c_yes),
        "c_no": str(package.c_no),
    }


def package_from_message(message: dict) -> AdminPackage:
    """Reconstruye el paquete recibido. Lanza: DomainError si es invalido.

    El censo debe ser el inicial: nadie llega marcado como votado.
    """
    try:
        entries = tuple(
            election.VoterEntry(
                e["id"],
                e["nombre"],
                e["mesa"],
                bytes.fromhex(e["estado"]) if e["estado"] else None,
            )
            for e in message["censo"]
        )
        codes = (message["c_si"], message["c_no"])
        if not all(isinstance(c, str) and c.isascii() and c.isdigit() for c in codes):
            raise ValueError
        package = AdminPackage(election.Census(entries), int(codes[0]), int(codes[1]))
    except (KeyError, TypeError, ValueError):
        raise DomainError(_BAD_PACKAGE) from None
    if package.census != election.initial_census():
        raise DomainError(_BAD_PACKAGE)
    return package


def _random_nonzero() -> int:
    return 1 + randomness.random_below(scheme.P - 1)


class Administrator:
    """Prepara el censo y los codigos de voto."""

    def prepare(self) -> AdminPackage:
        """Censo inicial y dos codigos distintos, no nulos, en [1, P-1]."""
        c_yes = _random_nonzero()
        c_no = _random_nonzero()
        while c_no == c_yes:
            c_no = _random_nonzero()
        return AdminPackage(election.initial_census(), c_yes, c_no)


class Skga:
    """Genera Kb (solo en memoria), los alfas y la urna inicial."""

    def __init__(self) -> None:
        self._kb: bytes | None = None

    # Solo para entregar Kb por canal a Recoleccion y Recuento.
    @property
    def kb(self) -> bytes:
        """Clave Kb. Lanza: DomainError si aun no se ha preparado la urna."""
        if self._kb is None:
            raise DomainError("La SKGA aun no ha generado la clave.")
        return self._kb

    def key_message(self) -> dict[str, object]:
        """Mensaje con Kb para entregarla a Recoleccion por un canal cifrado."""
        return {"kb": self.kb.hex()}

    def prepare(self, package: AdminPackage) -> election.Urn:
        """Genera Kb, eid, 10 alfas distintos y la fila de control sellada (0 x 10).

        Lanza: DomainError si ya hay Kb o los codigos no son validos.
        """
        if self._kb is not None:
            raise DomainError("La SKGA ya ha generado la clave de esta eleccion.")
        if not (
            package.c_yes != package.c_no
            and all(0 < c < scheme.P for c in (package.c_yes, package.c_no))
        ):
            raise DomainError("Codigos de voto no validos.")
        kb = aes_gcm.generate_key()
        eid = randomness.random_bytes(16)
        alphas: list[int] = []
        while len(alphas) < scheme.N_COLUMNS:
            a = _random_nonzero()
            if a not in alphas:
                alphas.append(a)
        control = tuple(
            sealing.seal_element(kb, 0, sealing.control_aad(eid.hex(), m, 0))
            for m in range(scheme.N_COLUMNS)
        )
        self._kb = kb
        return election.Urn(
            eid=eid,
            p=scheme.P,
            c_yes=package.c_yes,
            c_no=package.c_no,
            phase=election.Phase.OPEN,
            alphas=tuple(alphas),
            rows=(),
            control=control,
            result=None,
        )


_BAD_MESSAGE = "Mensaje de la votacion mal formado."
_CANNOT_VOTE = "No es posible registrar el voto."


@dataclass(frozen=True)
class Receipt:
    """Recibo del votante: polinomio p (a_0..a_11), columna h_t y codigo c."""

    voter_id: str
    coeffs: tuple[int, ...] = field(repr=False)
    h_t: int = field(repr=False)
    code: int = field(repr=False)


@dataclass(frozen=True)
class Offer:
    """Estado de Recoleccion entre enviar el polinomio y recibir la respuesta."""

    voter_id: str
    coeffs: tuple[int, ...] = field(repr=False)
    h_t: int = field(repr=False)
    control: tuple[int, ...] = field(repr=False)


def _element(value: object) -> int:
    """Entero decimal canonico en [0, P) desde texto. Lanza: DomainError si no lo es."""
    if not isinstance(value, str):
        raise DomainError(_BAD_MESSAGE)
    return scheme.parse_response(value)


def _kb_from_message(message: Mapping[str, object]) -> bytes:
    raw = message.get("kb")
    if not (
        isinstance(raw, str)
        and len(raw) == 2 * aes_gcm.KEY_SIZE
        and all(ch in "0123456789abcdef" for ch in raw)
    ):
        raise DomainError("Clave de la eleccion no valida.")
    return bytes.fromhex(raw)


class Collector:
    """Recoleccion: recibe Kb de la SKGA, reparte polinomios y confirma los votos."""

    def __init__(self, kb: bytes) -> None:
        if not isinstance(kb, bytes) or len(kb) != aes_gcm.KEY_SIZE:
            raise DomainError("Clave de la eleccion no valida.")
        self._kb = kb

    @classmethod
    def from_key_message(cls, message: Mapping[str, object]) -> Collector:
        """Recoleccion con la Kb recibida. Lanza: DomainError si el mensaje es invalido."""
        return cls(_kb_from_message(message))

    def offer(
        self, request: Mapping[str, object], urn: election.Urn, census: election.Census
    ) -> tuple[dict[str, object], Offer]:
        """Elige columna libre y polinomio de grado 11 para el votante de `request`.

        Devuelve el mensaje para el votante y el estado a conservar.
        Lanza: DomainError si el votante no puede votar, la fase no es abierta,
        no quedan columnas libres o Kb no abre marcas o control.
        """
        voter_id = request.get("id")
        if not isinstance(voter_id, str):
            raise DomainError(_BAD_MESSAGE)
        census.require_can_vote(voter_id)
        if len(urn.control) != scheme.N_COLUMNS:
            raise DomainError(_CANNOT_VOTE)
        if urn.phase is not election.Phase.OPEN:
            raise DomainError(_CANNOT_VOTE)
        eid = urn.eid.hex()
        used = {
            sealing.open_element(self._kb, e.mark, sealing.mark_aad(eid, e.id))
            for e in census.entries
            if e.mark is not None
        }
        n = len(urn.rows)
        control = tuple(
            sealing.open_element(self._kb, c, sealing.control_aad(eid, m, n))
            for m, c in enumerate(urn.control)
        )
        free = scheme.free_columns(used)
        if not free:
            raise DomainError(_CANNOT_VOTE)
        h_t = free[randomness.random_below(len(free))]
        coeffs = tuple(randomness.random_below(scheme.P) for _ in range(scheme.DEGREE)) + (
            _random_nonzero(),
        )
        message = {
            "coef": [str(a) for a in coeffs],
            "alfas": [str(a) for a in urn.alphas],
            "h_t": h_t,
        }
        return message, Offer(voter_id, coeffs, h_t, control)

    def accept(
        self,
        offer: Offer,
        reply: Mapping[str, object],
        urn: election.Urn,
        census: election.Census,
    ) -> tuple[election.Urn, election.Census]:
        """Urna y censo nuevos con la fila, el control resellado y la marca E_Kb(h_t).

        Lanza: DomainError si la respuesta no es un elemento valido o el censo/urna
        no admiten el voto.
        """
        response = _element(reply.get("respuesta"))
        row = scheme.vote_row(offer.coeffs, urn.alphas, offer.h_t, response)
        shifts = tuple(scheme.evaluate(offer.coeffs, a) for a in urn.alphas)
        control = scheme.add_columns(offer.control, shifts)
        eid, n = urn.eid.hex(), len(urn.rows) + 1
        sealed = tuple(
            sealing.seal_element(self._kb, v, sealing.control_aad(eid, m, n))
            for m, v in enumerate(control)
        )
        mark = sealing.seal_element(
            self._kb, offer.h_t, sealing.mark_aad(eid, offer.voter_id)
        )
        role = election.Role.COLLECTOR
        return (
            urn.with_vote(row, sealed, role=role),
            census.with_mark(offer.voter_id, mark, role=role),
        )


class Counter:
    """Recuento: recibe Kb solo al recontar y la descarta al terminar."""

    def count(
        self, key_message: Mapping[str, object], urn: election.Urn, census: election.Census
    ) -> election.Urn:
        """Abre control y marcas con Kb, calcula C = B - A y devuelve la urna escrutada.

        Se abre todo antes de calcular: si algo no autentica no hay resultado.
        Lanza: DomainError si la fase no es cerrada, Kb no es valida o algo no abre.
        """
        election.require_phase(urn, election.Phase.CLOSED)
        kb = _kb_from_message(key_message)
        try:
            eid, n = urn.eid.hex(), len(urn.rows)
            for e in census.entries:
                if e.mark is not None:
                    h_t = sealing.open_element(kb, e.mark, sealing.mark_aad(eid, e.id))
                    if not 1 <= h_t <= scheme.N_COLUMNS:
                        raise DomainError("Marca del censo no valida.")
            a = tuple(
                sealing.open_element(kb, c, sealing.control_aad(eid, m, n))
                for m, c in enumerate(urn.control)
            )
        finally:
            # Mejor esfuerzo: solo suelta la referencia; Python no borra los bytes.
            del kb
        result = scheme.tally(scheme.column_sums(urn.rows), a, urn.c_yes, urn.c_no)
        return urn.with_result(result, role=election.Role.COUNTER)


class Voter:
    """Votante: devuelve p(alfa_ht) + c segun su opcion."""

    def __init__(
        self, voter_id: str, c_yes: int, c_no: int, alphas: tuple[int, ...]
    ) -> None:
        self._id = voter_id
        self._alphas = tuple(alphas)
        self._codes = {
            scheme.Option.YES: c_yes,
            scheme.Option.NO: c_no,
            scheme.Option.ABSTAIN: 0,
        }

    def request(self) -> dict[str, object]:
        """Mensaje inicial hacia Recoleccion."""
        return {"id": self._id}

    def respond(
        self, offer: Mapping[str, object], option: scheme.Option
    ) -> tuple[dict[str, object], Receipt]:
        """Respuesta y recibo para el polinomio recibido.

        Lanza: DomainError si el mensaje o la opcion no son validos.
        """
        if not isinstance(option, scheme.Option):
            raise DomainError(_BAD_MESSAGE)
        coef, alfas, h_t = offer.get("coef"), offer.get("alfas"), offer.get("h_t")
        if (
            not isinstance(coef, list)
            or len(coef) != scheme.DEGREE + 1
            or not isinstance(alfas, list)
            or len(alfas) != scheme.N_COLUMNS
            or isinstance(h_t, bool)
            or not isinstance(h_t, int)
            or not 1 <= h_t <= scheme.N_COLUMNS
        ):
            raise DomainError(_BAD_MESSAGE)
        coeffs = tuple(_element(a) for a in coef)
        if tuple(_element(a) for a in alfas) != self._alphas:
            raise DomainError(_BAD_MESSAGE)
        alpha = self._alphas[h_t - 1]
        code = self._codes[option]
        value = (scheme.evaluate(coeffs, alpha) + code) % scheme.P
        return {"respuesta": str(value)}, Receipt(self._id, coeffs, h_t, code)
