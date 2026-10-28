"""Esquema publico (primo, dimensiones) y aritmetica mod P del voto."""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from enum import Enum

from evoting.core.errors import DomainError

# Primo del campo de NIST P-256 (FIPS 186-4): 2^256 - 2^224 + 2^192 + 2^96 - 1.
P: int = 2**256 - 2**224 + 2**192 + 2**96 - 1
N_COLUMNS: int = 10
DEGREE: int = 11
ELEMENT_SIZE: int = 32  # bytes de un elemento de Z_P serializado

_RESPONSE_RE = re.compile(r"[0-9]{1,78}")


class Option(Enum):
    """Opciones de voto."""

    YES = "YES"
    NO = "NO"
    ABSTAIN = "ABSTAIN"


def _check_element(value: int) -> None:
    if not 0 <= value < P:
        raise ValueError("value outside Z_P")


def evaluate(coeffs: Sequence[int], x: int) -> int:
    """Evalua por Horner mod P el polinomio de coeficientes a_0..a_11 en x.

    Lanza: ValueError si no hay DEGREE + 1 coeficientes o alguno/x esta fuera de Z_P.
    """
    if len(coeffs) != DEGREE + 1:
        raise ValueError("wrong number of coefficients")
    _check_element(x)
    acc = 0
    for a in reversed(coeffs):
        _check_element(a)
        acc = (acc * x + a) % P
    return acc


def vote_row(
    coeffs: Sequence[int], alphas: Sequence[int], h_t: int, response: int
) -> tuple[int, ...]:
    """Fila de urna: la respuesta en la columna h_t (1..10) y p(alfa_m) en el resto.

    Lanza: ValueError si h_t, response o las alfas no son validos.
    """
    if len(alphas) != N_COLUMNS or not 1 <= h_t <= N_COLUMNS:
        raise ValueError("invalid columns")
    _check_element(response)
    return tuple(
        response if m == h_t else evaluate(coeffs, alphas[m - 1])
        for m in range(1, N_COLUMNS + 1)
    )


def add_columns(a: Sequence[int], b: Sequence[int]) -> tuple[int, ...]:
    """Suma columna a columna mod P. Lanza: ValueError si no son N_COLUMNS elementos."""
    if len(a) != N_COLUMNS or len(b) != N_COLUMNS:
        raise ValueError("invalid columns")
    for v in (*a, *b):
        _check_element(v)
    return tuple((x + y) % P for x, y in zip(a, b))


def free_columns(used: Collection[int]) -> tuple[int, ...]:
    """Columnas (1..10) no usadas, en orden ascendente."""
    return tuple(m for m in range(1, N_COLUMNS + 1) if m not in used)


def parse_response(text: str) -> int:
    """Convierte la respuesta recibida (decimal, hasta 78 digitos) en un elemento de Z_P.

    Lanza: DomainError si no es decimal canonico o es >= P.
    """
    if not _RESPONSE_RE.fullmatch(text):
        raise DomainError("Respuesta no valida.")
    value = int(text)
    if value >= P:
        raise DomainError("Respuesta no valida.")
    return value


@dataclass(frozen=True)
class Result:
    """Recuento: C[1..10] y totales (abstencion = C 0; nulo = cualquier otro valor)."""

    columns: tuple[int, ...]
    yes: int
    no: int
    abstain: int
    null: int


def column_sums(rows: Sequence[Sequence[int]]) -> tuple[int, ...]:
    """Suma mod P de cada columna de la urna (ceros si no hay filas).

    Lanza: ValueError si una fila no tiene N_COLUMNS elementos de Z_P.
    """
    acc = (0,) * N_COLUMNS
    for row in rows:
        acc = add_columns(acc, row)
    return acc


def tally(
    b: Sequence[int], a: Sequence[int], c_yes: int, c_no: int
) -> Result:
    """Calcula C[m] = (B[m] - A[m]) mod P y clasifica: 0 abstencion, c_yes, c_no, nulo.

    Lanza: ValueError si b/a no son N_COLUMNS elementos de Z_P o los codigos son
    nulos o iguales.
    """
    if len(b) != N_COLUMNS or len(a) != N_COLUMNS:
        raise ValueError("invalid columns")
    if c_yes == c_no or 0 in (c_yes, c_no):
        raise ValueError("invalid vote codes")
    for v in (*b, *a, c_yes, c_no):
        _check_element(v)
    columns = tuple((x - y) % P for x, y in zip(b, a))
    return Result(
        columns=columns,
        yes=columns.count(c_yes),
        no=columns.count(c_no),
        abstain=columns.count(0),
        null=sum(1 for c in columns if c not in (0, c_yes, c_no)),
    )


def find_row(
    rows: Sequence[Sequence[int]],
    alphas: Sequence[int],
    coeffs: Sequence[int],
    h_t: int,
    code: int,
) -> int | None:
    """Indice de la primera fila con p(alfa_m) en todas las columnas salvo h_t, donde
    vale p(alfa_h_t) + code mod P; None si no hay ninguna.

    Lanza: ValueError si los parametros no son validos.
    """
    if len(alphas) != N_COLUMNS or not 1 <= h_t <= N_COLUMNS:
        raise ValueError("invalid columns")
    _check_element(code)
    base = tuple(evaluate(coeffs, al) for al in alphas)
    expected = tuple(
        (base[m] + code) % P if m == h_t - 1 else base[m] for m in range(N_COLUMNS)
    )
    for i, row in enumerate(rows):
        if tuple(row) == expected:
            return i
    return None
