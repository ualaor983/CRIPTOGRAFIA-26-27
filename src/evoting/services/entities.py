"""Entidades del sistema: SKGA, Recoleccion, Recuento y Votante.

Formatos (diccionarios que se guardan en JSON):
- urna:  {"alphas": [int], "control": [hex], "votes": [[int]], "result": [str] | None}
- censo: {"V01": {"mesa": "M1" | None, "mark": hex | None}, ...}
- codigos de voto: {"yes": [int], "no": [int]}
"""

from __future__ import annotations

import hashlib

from evoting.core import borrell_rifa
from evoting.core.errors import DomainError
from evoting.crypto import randomness
from evoting.services import sealing


class Skga:
    """Genera Kb con las aportaciones de la mesa e inicializa la urna."""

    def generate_kb(self, contributions: list[bytes]) -> bytes:
        """Kb = SHA-256(aleatorio || aportaciones de la mesa): 32 bytes."""
        return hashlib.sha256(randomness.random_bytes(32) + b"".join(contributions)).digest()

    def init_urn(self, kb: bytes, columns: int) -> dict:
        """Urna nueva: ``columns`` alfas aleatorios distintos y E_Kb(0) en el control."""
        alphas = []
        while len(alphas) < columns:
            alpha = randomness.random_below(borrell_rifa.P)
            if alpha != 0 and alpha not in alphas:
                alphas.append(alpha)
        return {
            "alphas": alphas,
            "control": sealing.seal_row(kb, [0] * columns),
            "votes": [],
            "result": None
        }


class Collector:
    """Recoleccion: atiende a cada votante y escribe voto, control y marca."""

    def __init__(self, kb: bytes, urn: dict, census: dict) -> None:
        self._kb = kb
        self.urn = urn
        self.census = census
        # votante -> (polinomio, columna) mientras su voto esta a medias.
        self._pending: dict[str, tuple[list[int], int]] = {}

    def start_vote(self, voter_id: str) -> dict:
        """Comprueba el censo y elige columna libre y polinomio; devuelve el mensaje.

        Mensaje: {"coeffs": [int], "alphas": [int], "column": int}.
        Lanza: DomainError si no esta en el censo, ya voto o no quedan columnas.
        """
        if voter_id not in self.census:
            raise DomainError("Votante fuera del censo.")
        if self.census[voter_id]["mark"] is not None:
            raise DomainError("El votante ya ha votado.")
        if voter_id in self._pending:
            raise DomainError("El votante ya tiene un voto en curso.")

        used = [column for _, column in self._pending.values()]
        for entry in self.census.values():
            if entry["mark"] is not None:
                used.append(sealing.unseal(self._kb, entry["mark"]))

        alphas = self.urn["alphas"]
        free = [i for i in range(len(alphas)) if i not in used]
        if not free:
            raise DomainError("No quedan columnas libres para votar.")

        column = free[randomness.random_below(len(free))]
        coeffs = [randomness.random_below(borrell_rifa.P) for _ in range(len(alphas) + 2)]
        self._pending[voter_id] = (coeffs, column)
        return {"coeffs": coeffs, "alphas": alphas, "column": column}

    def finish_vote(self, voter_id: str, answer: int) -> None:
        """Escribe la fila del voto, suma el polinomio al control y marca el censo.

        Lanza: DomainError si no tenia un voto empezado o ``answer`` no es valido.
        """
        if voter_id not in self._pending:
            raise DomainError("El votante no tiene un voto en curso.")
        # Viene del votante: un valor que no sea un entero romperia el recuento de todos.
        if type(answer) is not int or not 0 <= answer < borrell_rifa.P:
            raise DomainError("La respuesta del votante no es valida.")
        coeffs, column = self._pending.pop(voter_id)
        alphas = self.urn["alphas"]

        row = borrell_rifa.build_vote_row(coeffs, alphas, column, answer)
        control = sealing.unseal_row(self._kb, self.urn["control"])
        new_control = borrell_rifa.add_to_control(control, coeffs, alphas)

        self.urn["votes"].append(row)
        self.urn["control"] = sealing.seal_row(self._kb, new_control)
        self.census[voter_id]["mark"] = sealing.seal(self._kb, column)


class Counter:
    """Recuento: descifra el control, resta y publica el resultado por columna."""

    def count(self, kb: bytes, urn: dict, codes: dict) -> list[str]:
        """Escribe en ``urn["result"]`` y devuelve la interpretacion de cada columna."""
        control = sealing.unseal_row(kb, urn["control"])
        values = borrell_rifa.tally(urn["votes"], control)
        result = [
            borrell_rifa.interpret(value, codes["yes"], codes["no"])
            for value in values
        ]
        urn["result"] = result
        return result


class Voter:
    """Votante: responde con p(alfa_h) + c y guarda su recibo para verificar."""

    def __init__(self, voter_id: str, choice: str, codes: dict) -> None:
        self.voter_id = voter_id
        self.codes = codes  # C_Si y C_No publicados por el Administrador
        self.choice = choice  # borrell_rifa.YES, borrell_rifa.NO u otro (voto nulo)
        self.receipt: dict | None = None

    def answer(self, request: dict) -> int:
        """Calcula su respuesta a partir del mensaje de la recoleccion y guarda el recibo."""
        if self.choice == borrell_rifa.YES:
            options = self.codes["yes"]
        elif self.choice == borrell_rifa.NO:
            options = self.codes["no"]
        elif self.choice == borrell_rifa.ABSTENTION:
            options = [0]  # En blanco: la columna suma 0, como una que nadie uso
        else:
            options = [99]  # Voto nulo
        code = options[randomness.random_below(len(options))]
        alpha = request["alphas"][request["column"]]
        self.receipt = {**request, "code": code}
        return borrell_rifa.voter_answer(request["coeffs"], alpha, code)

    def verify(self, urn: dict) -> bool:
        """True si su fila esta en la urna y el resultado de su columna es su opcion."""
        if self.receipt is None or urn["result"] is None:
            return False

        coeffs = self.receipt["coeffs"]
        alphas = self.receipt["alphas"]
        column = self.receipt["column"]
        code = self.receipt["code"]

        answer = borrell_rifa.voter_answer(coeffs, alphas[column], code)
        row = borrell_rifa.build_vote_row(coeffs, alphas, column, answer)
        if row not in urn["votes"]:
            return False

        expected = borrell_rifa.interpret(code, self.codes["yes"], self.codes["no"])
        return urn["result"][column] == expected
