"""Primos grandes aleatorios con el test de Miller-Rabin (temario: D06, diapositivas 13-14).

Es la unica excepcion a "no implementar primitivas propias": el test esta en el
temario y es solo aritmetica. Las bases y los candidatos salen de ``randomness``.
"""

from __future__ import annotations

from evoting.crypto import randomness

# Con cada base, un compuesto pasa el test con probabilidad <= 1/4.
# Con 40 bases independientes: error <= (1/4)^40 = 2^-80.
ROUNDS: int = 40


def is_probable_prime(n: int, rounds: int = ROUNDS) -> bool:
    """Miller-Rabin: False si ``n`` es compuesto seguro; True si es primo con error <= 4^-rounds.

    Si p es primo impar y p - 1 = 2^k * d con d impar, para toda base a se cumple
    a^d = 1 (mod p) o a^(d * 2^r) = -1 (mod p) para algun r en [0, k-1].
    Una base que no lo cumple es un testigo de que n es compuesto.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # n - 1 = 2^k * d, con d impar.
    k = 0
    d = n - 1
    while d % 2 == 0:
        d = d // 2
        k = k + 1

    for _ in range(rounds):
        a = 2 + randomness.random_below(n - 3)  # base aleatoria en [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue  # a^d = 1 o a^d = -1: esta base no demuestra nada
        found_minus_one = False
        for _ in range(k - 1):
            x = pow(x, 2, n)  # a^(d * 2^r) para r = 1, ..., k-1
            if x == n - 1:
                found_minus_one = True
                break
        if not found_minus_one:
            return False  # a es testigo: n es compuesto
    return True


def random_prime(bits: int) -> int:
    """Primo aleatorio de exactamente ``bits`` bits.

    Toma un numero aleatorio de ``bits`` bits, fuerza a 1 el bit alto (para que
    tenga esa longitud) y el bajo (para que sea impar), y repite hasta que pase
    Miller-Rabin. Lanza: ValueError si ``bits`` es menor que 3.
    """
    if bits < 3:
        raise ValueError("bits debe ser al menos 3")
    while True:
        candidate = randomness.random_below(2**bits)
        candidate = candidate | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
