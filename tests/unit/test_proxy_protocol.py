"""Exposition des leurres par le relais d'entrée (ADR 008, #52).

Docker ne publie pas les ports d'un conteneur relié seulement à des réseaux internes.
Les leurres restent donc isolés, et le relais leur transmet l'adresse réelle de
l'attaquant dans un en-tête PROXY protocol v1.
"""

import asyncio
import json

import httpx
import pytest
import yaml

from shield.decoys.base import parse_proxy_header
from shield.decoys.ssh import SSHDecoy

COMPOSE = yaml.safe_load(open("docker-compose.yml", encoding="utf-8"))
DECOYS = [name for name in COMPOSE["services"] if name.startswith("decoy-")]


# ------------------------------------------------------------------ en-tête PROXY v1


@pytest.mark.parametrize(
    "line,expected",
    [
        (b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22\r\n", ("203.0.113.9", 51000)),
        (b"PROXY TCP6 2001:db8::7 2001:db8::1 40000 21\r\n", ("2001:db8::7", 40000)),
        (b"PROXY UNKNOWN\r\n", None),
    ],
)
def test_un_en_tete_proxy_valide_donne_l_adresse_reelle(line, expected):
    assert parse_proxy_header(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        b"SSH-2.0-libssh\r\n",  # un client direct, pas le relais
        b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22",  # pas de fin de ligne
        b"PROXY TCP4 2001:db8::7 192.0.2.1 51000 22\r\n",  # famille incohérente
        b"PROXY TCP4 pas-une-ip 192.0.2.1 51000 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 70000 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 -1 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1\r\n",
        b"PROXY TCP4 \xff\xfe 192.0.2.1 51000 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22 " + b"x" * 100 + b"\r\n",
    ],
)
def test_un_en_tete_proxy_invalide_est_refuse(line):
    with pytest.raises(ValueError):
        parse_proxy_header(line)


# ------------------------------------------------------------------ leurre en écoute


@pytest.fixture
async def ssh_decoy():
    """Un leurre SSH réel, derrière le relais, dont les émissions sont capturées."""
    emitted: list[dict] = []
    received = asyncio.Event()

    def capture(request: httpx.Request) -> httpx.Response:
        emitted.append(json.loads(request.content))
        received.set()
        return httpx.Response(202)

    decoy = SSHDecoy(
        port=0,
        ingest_url="http://collector/api/v1/ingest",
        ingest_token="t",
        banner="SSH-2.0-OpenSSH_8.9p1",
        proxy_protocol=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(capture)),
    )
    await decoy.start()
    port = decoy._server.sockets[0].getsockname()[1]
    yield port, emitted, received
    await decoy.stop()


async def test_l_evenement_porte_l_adresse_de_l_attaquant_pas_celle_du_relais(ssh_decoy):
    port, emitted, received = ssh_decoy
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22\r\n")
    assert (await reader.readline()).startswith(b"SSH-2.0-")
    writer.write(b"root:toor\r\n")
    await writer.drain()
    await asyncio.wait_for(received.wait(), timeout=5)
    writer.close()

    [event] = emitted
    assert (event["source_ip"], event["source_port"]) == ("203.0.113.9", 51000)
    assert (event["username"], event["password"]) == ("root", "toor")


async def test_sans_en_tete_du_relais_la_connexion_est_fermee_sans_evenement(ssh_decoy):
    port, emitted, _ = ssh_decoy
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"SSH-2.0-libssh\r\nroot:toor\r\n")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    writer.close()
    assert emitted == []


# ------------------------------------------------------------------ compose


@pytest.mark.parametrize("decoy", DECOYS)
def test_un_leurre_n_est_relie_qu_a_des_reseaux_internes(decoy):
    """Invariant 4 : aucune sortie réseau depuis la zone des leurres."""
    service = COMPOSE["services"][decoy]
    assert "ports" not in service, "Docker ignore la publication sur un réseau interne"
    for network in service["networks"]:
        assert COMPOSE["networks"][network].get("internal") is True, network
    assert service["environment"]["DECOY_PROXY_PROTOCOL"] == "1"


def test_le_relais_expose_chaque_leurre():
    edge = COMPOSE["services"]["edge"]
    assert set(edge["depends_on"]) == set(DECOYS)
    assert len(edge["ports"]) == len(DECOYS)
