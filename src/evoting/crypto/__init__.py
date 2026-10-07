"""Primitivas y protocolos criptograficos.

Reglas de la capa:

- **Prohibido implementar primitivas propias.** Se envuelve ``cryptography`` y
  la libreria estandar (``hashlib``, ``hmac``, ``secrets``).
- Aleatoriedad **solo** desde ``evoting.crypto.randomness``, que usa ``secrets``.
  El modulo ``random`` esta prohibido en todo el proyecto.
- Prohibidas las primitivas rotas: MD5, SHA-1, DES/3DES, RC4, modo ECB y
  RSA PKCS#1 v1.5 para cifrado. Si una practica exige usar alguna con fines
  didacticos, se aisla en ``crypto/legacy/`` documentando por que esta rota.
- Esta capa no conoce el modelo de dominio: trabaja con ``bytes``.
"""
