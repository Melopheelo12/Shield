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

from shield.decoys.base import parse_proxy_header, parse_public_ports
from shield.decoys.http import HTTPDecoy
from shield.decoys.ssh import SSHDecoy

COMPOSE = yaml.safe_load(open("docker-compose.yml", encoding="utf-8"))
DECOYS = [name for name in COMPOSE["services"] if name.startswith("decoy-")]


# ------------------------------------------------------------------ en-tête PROXY v1


@pytest.mark.parametrize(
    "line,expected",
    [
        (b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22\r\n", ("203.0.113.9", 51000, 22)),
        (b"PROXY TCP6 2001:db8::7 2001:db8::1 40000 21\r\n", ("2001:db8::7", 40000, 21)),
        (b"PROXY UNKNOWN\r\n", None),
    ],
)
def test_un_en_tete_proxy_valide_donne_l_adresse_reelle_et_le_port_vise(line, expected):
    assert parse_proxy_header(line) == expected


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("", {}),
        ("4443=443", {4443: 443}),
        (" 2222=22 , 8080=80,2121=21,4443=443 ", {2222: 22, 8080: 80, 2121: 21, 4443: 443}),
    ],
)
def test_correspondance_des_ports_publics(spec, expected):
    assert parse_public_ports(spec) == expected


@pytest.mark.parametrize("spec", ["4443", "4443=", "x=443", "4443=70000", "=443"])
def test_une_correspondance_invalide_arrete_le_leurre(spec):
    with pytest.raises(ValueError):
        parse_public_ports(spec)


@pytest.mark.parametrize(
    "line",
    [
        b"SSH-2.0-libssh\r\n",  # un client direct, pas le relais
        b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 22",  # pas de fin de ligne
        b"PROXY TCP4 2001:db8::7 192.0.2.1 51000 22\r\n",  # famille incohérente
        b"PROXY TCP4 pas-une-ip 192.0.2.1 51000 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 70000 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 -1 22\r\n",
        b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 99999\r\n",  # port de destination
        b"PROXY TCP4 203.0.113.9 192.0.2.1 51000 https\r\n",
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


async def http_event_through_relay(proxy_line: bytes | None) -> dict:
    """Une requête vers un leurre HTTP réel, avec ou sans le relais devant."""
    emitted: list[dict] = []
    received = asyncio.Event()

    def capture(request: httpx.Request) -> httpx.Response:
        emitted.append(json.loads(request.content))
        received.set()
        return httpx.Response(202)

    decoy = HTTPDecoy(
        port=0,
        ingest_url="http://collector/api/v1/ingest",
        ingest_token="t",
        proxy_protocol=proxy_line is not None,
        public_ports=parse_public_ports("8080=80,4443=443"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(capture)),
    )
    await decoy.start()
    try:
        port = decoy._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write((proxy_line or b"") + b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)
        await asyncio.wait_for(received.wait(), timeout=5)
        writer.close()
    finally:
        await decoy.stop()
    [event] = emitted
    return event


@pytest.mark.parametrize(
    "relay_port,public_port",
    [(4443, 443), (8080, 80), (9000, 9000)],  # 9000 : hors correspondance, gardé tel quel
)
async def test_l_evenement_porte_le_port_public_vise(relay_port, public_port):
    """#97 : HTTPS (4443 → 443) et HTTP (8080 → 80) mènent au même leurre, mais
    l'événement dit lequel a été attaqué."""
    line = f"PROXY TCP4 203.0.113.9 192.0.2.1 51000 {relay_port}\r\n".encode()
    event = await http_event_through_relay(line)
    assert event["dest_port"] == public_port
    assert event["source_ip"] == "203.0.113.9"


async def test_sans_relais_le_port_est_celui_d_ecoute():
    event = await http_event_through_relay(None)
    assert event["dest_port"] == 0  # port d'écoute du leurre de test (port=0)


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


@pytest.mark.parametrize("decoy", DECOYS)
def test_chaque_port_du_relais_a_son_port_public(decoy):
    """Chaque port interne publié par edge se traduit en port public dans les événements."""
    mapping = COMPOSE["services"][decoy]["environment"]["DECOY_PUBLIC_PORTS"]
    internal = {int(entry.split("=")[0]) for entry in mapping.split(",")}
    published = {int(port.split(":")[-1]) for port in COMPOSE["services"]["edge"]["ports"]}
    assert published <= internal


def test_le_relais_expose_chaque_leurre():
    edge = COMPOSE["services"]["edge"]
    assert set(edge["depends_on"]) == set(DECOYS)
    assert len(edge["ports"]) == len(DECOYS)


def test_le_relais_ne_coupe_pas_le_leurre_quand_le_client_ferme_son_ecriture():
    """Invariant 1 : un client qui envoie puis ferme son côté écriture (`nc < fichier`)
    doit encore produire un événement. Sans `proxy_half_close`, nginx coupe aussi la
    connexion vers le leurre, qui n'émet rien en SSH ni en FTP."""
    with open("deploy/edge.conf", encoding="utf-8") as handle:
        directives = [line.split("#")[0].strip() for line in handle]
    assert "proxy_half_close on;" in directives
