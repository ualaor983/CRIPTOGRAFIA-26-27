"""Modelo de dominio puro.

Reglas de la capa:

- Sin IO (ni ficheros, ni red, ni base de datos).
- Sin criptografia: aqui no se cifra, ni se firma, ni se calculan hashes.
- Sin PyQt6.

Si algo de esto hace falta, pertenece a ``services``, ``crypto`` o ``storage``.
"""
