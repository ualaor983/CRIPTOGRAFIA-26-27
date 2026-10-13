"""Excepciones de dominio del sistema."""

from __future__ import annotations


class DomainError(Exception):
    """Fallo explícito de una operación; su mensaje se muestra tal cual al usuario.

    El mensaje es un texto fijo: nunca incluye la clave ni el contenido.
    """
