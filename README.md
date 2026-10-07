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
