"""Entidades del sistema: Administrador, SKGA, Recoleccion, Recuento y Votante.

Cada entidad es un ``Participant``: tiene su propio par de claves Kyber, que le
entrega el Administrador (Entidad Certificadora) al preparar la eleccion.

Formatos (diccionarios que se guardan en JSON):
- urna:  {"alphas": [int], "control": [hex], "votes": [[int]], "result": [str] | None}
- censo: {"V01": {"mesa": "M1" | None, "mark": hex | None}, ...}
- codigos de voto: {"p": int, "yes": [int], "no": [int]} (p es el primo de la eleccion)
- directorio: {"Administrador": hex, "SKGA": hex, ..., "V01": hex, ...} (claves publicas)
"""

from __future__ import annotations

import hashlib

from evoting.core import borrell_rifa
from evoting.core.errors import DomainError
from evoting.crypto import kyber, primes, randomness
from evoting.services import sealing


class Participant:
    """Quien participa en la eleccion: tiene un nombre y su propio par de claves Kyber."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.public_key = b""
        self._secret_key = b""  # Solo la tiene este objeto: nadie mas la guarda.

    def receive_keys(self, public_key: bytes, secret_key: bytes) -> None:
        """Recibe su par del Administrador.

        La entrega es por un canal seguro fuera de la red (en persona, como el DNIe):
        aun no hay ninguna clave con la que cifrarla.
        """
        self.public_key = public_key
        self._secret_key = secret_key


class Administrator(Participant):
    """Administrador y Entidad Certificadora: parametros publicos, censo y pares de claves."""

    def __init__(self) -> None:
        super().__init__("Administrador")
        # Su propio par: es el unico par que guarda.
        public_key, secret_key = kyber.generate_keypair()
        self.receive_keys(public_key, secret_key)
        # Directorio publico de claves publicas: nombre -> clave publica en hex.
        self.directory: dict[str, str] = {self.name: public_key.hex()}

    def generate_prime(self, bits: int) -> int:
        """Primo p de la eleccion, nuevo cada vez que se inicializa el sistema."""
        return primes.random_prime(bits)

    def create_census(self, voter_ids: list[str], mesa_size: int) -> dict:
        """Censo nuevo: los ``mesa_size`` primeros son la mesa (M1, M2...); nadie ha votado."""
        census = {}
        for position, voter_id in enumerate(voter_ids):
            if position < mesa_size:
                mesa = f"M{position + 1}"
            else:
                mesa = None
            census[voter_id] = {"mesa": mesa, "mark": None}
        return census

    def create_vote_codes(self, p: int, size: int) -> dict:
        """Primo p y conjuntos publicos C_Si y C_No, con ``size`` valores cada uno.

        Devuelve {"p": int, "yes": [int], "no": [int]}: valores en [1, p), todos distintos.
        """
        values = []
        while len(values) < 2 * size:
            candidate = randomness.random_below(p)
            if candidate != 0 and candidate not in values:
                values.append(candidate)
        return {
            "p": p,
            "yes": values[:size],
            "no": values[size:]
        }

    def issue_keys(self, participant: Participant) -> None:
        """Crea el par de ``participant``, se lo entrega y publica su clave publica.

        La clave privada solo existe en esta variable local: al terminar el metodo,
        el Administrador ya no la tiene. Lo unico que anota es la clave publica.
        """
        public_key, secret_key = kyber.generate_keypair()
        participant.receive_keys(public_key, secret_key)
        self.directory[participant.name] = public_key.hex()


class Skga(Participant):
    """Genera Kb con las aportaciones de la mesa e inicializa la urna."""

    def __init__(self) -> None:
        super().__init__("SKGA")

    def generate_kb(self, contributions: list[bytes]) -> bytes:
        """Kb = SHA-256(aleatorio || aportaciones de la mesa): 32 bytes."""
        return hashlib.sha256(randomness.random_bytes(32) + b"".join(contributions)).digest()

    def init_urn(self, kb: bytes, columns: int, p: int) -> dict:
        """Urna nueva: ``columns`` alfas aleatorios distintos en Z_p y E_Kb(0) en el control."""
        alphas = []
        while len(alphas) < columns:
            alpha = randomness.random_below(p)
            if alpha != 0 and alpha not in alphas:
                alphas.append(alpha)
        return {
            "alphas": alphas,
            "control": sealing.seal_row(kb, [0] * columns),
            "votes": [],
            "result": None
        }


class Collector(Participant):
    """Recoleccion: atiende a cada votante y escribe voto, control y marca."""

    def __init__(self) -> None:
        super().__init__("Recoleccion")
        self._kb = b""
        self.urn: dict = {}
        self.census: dict = {}
        self._p = 0
        # votante -> (polinomio, columna) mientras su voto esta a medias.
        self._pending: dict[str, tuple[list[int], int]] = {}

    def prepare(self, kb: bytes, urn: dict, census: dict, p: int) -> None:
        """Recibe Kb (del SKGA), la urna, el censo y el primo p, y queda lista para votar."""
        self._kb = kb
        self.urn = urn
        self.census = census
        self._p = p

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
        coeffs = [randomness.random_below(self._p) for _ in range(len(alphas) + 2)]
        self._pending[voter_id] = (coeffs, column)
        return {"coeffs": coeffs, "alphas": alphas, "column": column}

    def finish_vote(self, voter_id: str, answer: int) -> None:
        """Escribe la fila del voto, suma el polinomio al control y marca el censo.

        Lanza: DomainError si no tenia un voto empezado o ``answer`` no es valido.
        """
        if voter_id not in self._pending:
            raise DomainError("El votante no tiene un voto en curso.")
        # Viene del votante: un valor que no sea un entero romperia el recuento de todos.
        if type(answer) is not int or not 0 <= answer < self._p:
            raise DomainError("La respuesta del votante no es valida.")
        coeffs, column = self._pending.pop(voter_id)
        alphas = self.urn["alphas"]

        row = borrell_rifa.build_vote_row(coeffs, alphas, column, answer, self._p)
        control = sealing.unseal_row(self._kb, self.urn["control"])
        new_control = borrell_rifa.add_to_control(control, coeffs, alphas, self._p)

        self.urn["votes"].append(row)
        self.urn["control"] = sealing.seal_row(self._kb, new_control)
        self.census[voter_id]["mark"] = sealing.seal(self._kb, column)


class Counter(Participant):
    """Recuento: descifra el control, resta y publica el resultado por columna."""

    def __init__(self) -> None:
        super().__init__("Recuento")

    def count(self, kb: bytes, urn: dict, codes: dict) -> list[str]:
        """Escribe en ``urn["result"]`` y devuelve la interpretacion de cada columna."""
        control = sealing.unseal_row(kb, urn["control"])
        values = borrell_rifa.tally(urn["votes"], control, codes["p"])
        result = [
            borrell_rifa.interpret(value, codes["yes"], codes["no"])
            for value in values
        ]
        urn["result"] = result
        return result


class Voter(Participant):
    """Votante: responde con p(alfa_h) + c y guarda su recibo para verificar."""

    def __init__(self, voter_id: str, codes: dict) -> None:
        super().__init__(voter_id)
        self.voter_id = voter_id
        self.codes = codes  # p, C_Si y C_No publicados por el Administrador
        self.receipt: dict | None = None

    def answer(self, request: dict, choice: str) -> int:
        """Calcula su respuesta a partir del mensaje de la recoleccion y guarda el recibo.

        ``choice``: borrell_rifa.YES, borrell_rifa.NO, borrell_rifa.ABSTENTION u otro (nulo).
        """
        if choice == borrell_rifa.YES:
            options = self.codes["yes"]
        elif choice == borrell_rifa.NO:
            options = self.codes["no"]
        elif choice == borrell_rifa.ABSTENTION:
            options = [0]  # En blanco: la columna suma 0, como una que nadie uso
        else:
            options = [99]  # Voto nulo
        code = options[randomness.random_below(len(options))]
        alpha = request["alphas"][request["column"]]
        self.receipt = {**request, "code": code}
        return borrell_rifa.voter_answer(request["coeffs"], alpha, code, self.codes["p"])

    def verify(self, urn: dict) -> bool:
        """True si su fila esta en la urna y el resultado de su columna es su opcion."""
        if self.receipt is None or urn["result"] is None:
            return False

        coeffs = self.receipt["coeffs"]
        alphas = self.receipt["alphas"]
        column = self.receipt["column"]
        code = self.receipt["code"]

        p = self.codes["p"]
        answer = borrell_rifa.voter_answer(coeffs, alphas[column], code, p)
        row = borrell_rifa.build_vote_row(coeffs, alphas, column, answer, p)
        if row not in urn["votes"]:
            return False

        expected = borrell_rifa.interpret(code, self.codes["yes"], self.codes["no"])
        return urn["result"][column] == expected
