"""Ciclo completo de una eleccion: preparacion, votacion, cierre y recuento.

Todo mensaje entre entidades pasa por un ``Channel`` cifrado con AES-GCM.
"""

from __future__ import annotations

from pathlib import Path

from evoting.core import borrell_rifa
from evoting.core.errors import DomainError
from evoting.crypto import randomness
from evoting.services.channel import Channel
from evoting.services.entities import Collector, Counter, Skga, Voter
from evoting.storage import json_files

VOTERS: int = 10
MESA: int = 4
CODES_PER_OPTION: int = 10


def create_census(voter_ids: list[str]) -> dict:
    """Censo nuevo: los MESA primeros son la mesa (M1..M4); nadie ha votado."""
    census = {}
    for position, voter_id in enumerate(voter_ids):
        if position < MESA:
            mesa = f"M{position + 1}"
        else:
            mesa = None
        census[voter_id] = {"mesa": mesa, "mark": None}
    return census


def create_vote_codes(size: int = CODES_PER_OPTION) -> dict[str, list[int]]:
    """Administrador: conjuntos publicos C_Si y C_No, con ``size`` valores cada uno.

    Devuelve {"yes": [int], "no": [int]}: valores en [1, P), todos distintos entre si.
    """
    values = []
    while len(values) < 2 * size:
        candidate = randomness.random_below(borrell_rifa.P)
        if candidate != 0 and candidate not in values:
            values.append(candidate)
    return {
        "yes": values[:size],
        "no": values[size:]
    }


def _transmit(channel: Channel, message: dict) -> dict:
    return channel.receive(channel.send(message))


def run_election(choices: dict[str, str], data_dir: Path) -> list[str]:
    """Ejecuta la eleccion con el voto de cada votante y devuelve el resultado por columna.

    ``choices``: {"V01": "si", "V02": "no", ...}. Guarda urna, censo y codigos en data_dir.
    """
    census_path = data_dir / "censo.json"
    urn_path = data_dir / "urna.json"
    codes_path = data_dir / "codigos.json"

    # 1. Administrador: censo y codigos publicos.
    census = create_census(list(choices))
    codes = create_vote_codes()
    json_files.save(census_path, census)
    json_files.save(codes_path, codes)

    # 2. Mesa -> SKGA: aportaciones; el SKGA genera Kb e inicializa la urna.
    skga = Skga()
    contributions = []
    for entry in census.values():
        if entry["mesa"] is not None:
            channel = Channel(entry["mesa"], "SKGA")
            message = _transmit(channel, {"value": randomness.random_bytes(32).hex()})
            contributions.append(bytes.fromhex(message["value"]))
    kb = skga.generate_kb(contributions)
    urn = skga.init_urn(kb, len(choices))
    json_files.save(urn_path, urn)

    # 3. SKGA -> Recoleccion: Kb.
    message = _transmit(Channel("SKGA", "Recoleccion"), {"kb": kb.hex()})
    collector = Collector(bytes.fromhex(message["kb"]), urn, census)

    # 4. Votacion: un canal por sentido y por votante.
    voters = []
    for voter_id, choice in choices.items():
        voter = Voter(voter_id, choice, codes)
        voters.append(voter)
        to_voter = Channel("Recoleccion", voter_id)
        to_collector = Channel(voter_id, "Recoleccion")
        request = _transmit(to_voter, collector.start_vote(voter_id))
        reply = _transmit(to_collector, {"answer": voter.answer(request)})
        collector.finish_vote(voter_id, reply["answer"])
        json_files.save(urn_path, urn)
        json_files.save(census_path, census)

    # 5 y 6. Cierre: SKGA -> Recuento: Kb; recuento y publicacion.
    message = _transmit(Channel("SKGA", "Recuento"), {"kb": kb.hex()})
    result = Counter().count(bytes.fromhex(message["kb"]), urn, codes)
    json_files.save(urn_path, urn)

    # 7. Cada votante descarga la urna publica y verifica su voto.
    public_urn = json_files.load(urn_path)
    if not all(voter.verify(public_urn) for voter in voters):
        raise DomainError("Un votante no ha podido verificar su voto.")
    return result
