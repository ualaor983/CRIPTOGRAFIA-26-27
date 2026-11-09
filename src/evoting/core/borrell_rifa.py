"""Matematica del esquema Borrell-Rifa: polinomios mod P, filas de voto y recuento.

Solo calculos con enteros: sin aleatoriedad, sin cifrado y sin ficheros.
"""

from __future__ import annotations

# Primo de Mersenne 2^127 - 1: todas las cuentas del voto se hacen modulo P.
P: int = 2**127 - 1

YES: str = "si"
NO: str = "no"
ABSTENTION: str = "abstencion"
NULL: str = "nulo"


def evaluate(coeffs: list[int], x: int) -> int:
    """Valor del polinomio en ``x`` modulo P.

    ``coeffs[i]`` es el coeficiente de x^i: [4, 7] es 4 + 7x.
    """
    result = 0
    for i, a in enumerate(coeffs):
        term = a * pow(x, i, P) % P
        result += term
    return result % P


def voter_answer(coeffs: list[int], alpha: int, code: int) -> int:
    """Lo que calcula el votante: p(alfa de su columna) + c, modulo P."""
    return (evaluate(coeffs, alpha) + code) % P


def build_vote_row(
    coeffs: list[int], alphas: list[int], column: int, answer: int
) -> list[int]:
    """Fila de un voto: p(alfa_m) en cada columna m, salvo ``column``, que lleva ``answer``.

    ``column`` empieza en 0.
    """
    row = [evaluate(coeffs, a) for a in alphas]
    row[column] = answer
    return row


def add_to_control(
    control: list[int], coeffs: list[int], alphas: list[int]
) -> list[int]:
    """Nueva fila de control: control[m] + p(alfa_m) modulo P, para cada columna.

    Se suma el polinomio SIN el voto: asi el recuento cancela los polinomios.
    """
    new_control = []
    for c, a in zip(control, alphas):
        new_control.append((c + evaluate(coeffs, a)) % P)
    return new_control


def tally(vote_rows: list[list[int]], control: list[int]) -> list[int]:
    """Por columna: suma de las filas de voto menos el control, modulo P.

    Lo que queda en cada columna es el codigo c de quien la uso (o 0).
    """
    result = []
    for m in range(len(control)):
        column_sum = sum(row[m] for row in vote_rows)
        result.append((column_sum - control[m]) % P)
    return result


def interpret(value: int, yes_codes: list[int], no_codes: list[int]) -> str:
    """Traduce una columna: 0 abstencion, en yes_codes si, en no_codes no, otro nulo."""
    if value == 0:
        return ABSTENTION
    elif value in yes_codes:
        return YES
    elif value in no_codes:
        return NO
    else:
        return NULL
