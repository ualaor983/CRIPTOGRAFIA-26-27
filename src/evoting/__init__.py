"""Sistema de voto electronico — practica de Criptografia 26/27.

Arquitectura en capas, con dependencias en una sola direccion::

    ui  ->  services  ->  core
                      ->  crypto
                      ->  storage

- ``core``     modelo de dominio puro: sin IO, sin criptografia, sin Qt.
- ``crypto``   primitivas y protocolos criptograficos: sin modelo de dominio.
- ``storage``  persistencia detras de interfaces.
- ``services`` casos de uso; orquesta core + crypto + storage.
- ``ui``       presentacion de escritorio (PyQt6); sin logica de negocio.
"""

__version__ = "0.1.0"
