# Sistema de Voto Electronico — Criptografia 26/27

Practica de la asignatura de Criptografia. Aplicacion de **escritorio** en
Python para la gestion de un proceso de voto electronico.

## Requisitos

- Python >= 3.12
- Dependencias: `python -m pip install -r requirements.txt`

## Instalacion para desarrollo

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

## Ejecucion

```bash
python -m evoting
```

Demostracion por consola (10 votos, recuento y verificacion):

```bash
python -m evoting.ui.console
```

## Criptografia (estado: Actividad 4)

- **Esquema de voto** Borrell-Rifa en Z_p. El primo `p` (128 bits) se genera al
  azar con Miller-Rabin cada vez que se prepara una eleccion (`crypto/primes.py`).
- **Administrador = Entidad Certificadora.** Crea el par de claves Kyber de cada
  participante (SKGA, Recoleccion, Recuento y votantes), se lo entrega y publica
  las claves publicas en `data/directorio.json`. Solo guarda su propio par.
- **Comunicaciones:** el emisor encapsula con Kyber (ML-KEM-768, `crypto/kyber.py`)
  una clave AES-256 nueva para la clave publica del receptor; el mensaje va con
  AES-256-GCM. Cada comunicacion y cada sentido usan una clave distinta.
- **Urna y censo:** la fila de control y las marcas del censo se cifran con la
  clave de la urna `Kb` (AES-256-GCM).
- Pendiente: firmas y certificados firmados (Dilithium) y reparto de `Kb` (SKRA).

Ficheros publicos que se escriben en `data/`: `codigos.json` (`p`, C_Si, C_No),
`directorio.json`, `censo.json` y `urna.json`.

## Estructura

```
src/evoting/
├── core/        modelo de dominio puro (sin IO, sin criptografia, sin Qt)
├── crypto/      primitivas y protocolos criptograficos
├── storage/     persistencia (censo, urna, actas, auditoria)
├── services/    casos de uso; orquesta core + crypto + storage
└── ui/          interfaz de escritorio (PyQt6), solo presentacion
docs/            documentacion de la practica
```

Dependencias entre capas en una sola direccion:

```
ui  ->  services  ->  core
                  ->  crypto
                  ->  storage
```

## Convenciones

- Docstrings y comentarios en castellano; identificadores en ingles.
- Ninguna clave, secreto ni dato de censo se versiona (`keys/`, `data/`, `*.pem`
  estan ignorados).
- Commits en imperativo y castellano, con alcance:
  `feat(crypto): añade firma ciega sobre RSA`.
