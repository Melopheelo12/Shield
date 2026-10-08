"""Les leurres doivent analyser sans jamais interpréter, et ne jamais se trahir."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from shield.decoys.ftp import FTPDecoy
from shield.decoys.http import HTTPDecoy
from shield.decoys.ssh import SSHDecoy

DECOY_SOURCES = list(Path("src/shield/decoys").glob("*.py"))
FORBIDDEN = ("eval(", "exec(", "subprocess", "os.system", "pickle.loads", "__import__")


@pytest.mark.parametrize("source", DECOY_SOURCES, ids=lambda p: p.name)
def test_aucun_leurre_ne_peut_executer_quoi_que_ce_soit(source):
    """Invariant de sécurité R1, vérifié automatiquement à chaque exécution de la CI."""
    text = source.read_text(encoding="utf-8")
    # On ignore les docstrings et commentaires qui citent ces mots volontairement.
    code = "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#") and "``" not in line
    )
    for needle in FORBIDDEN:
        assert needle not in code, f"{source.name} contient {needle!r}"


@pytest.mark.parametrize("source", DECOY_SOURCES, ids=lambda p: p.name)
def test_aucun_leurre_ne_revele_son_identite(source):
    """Une réponse réseau ne doit jamais contenir « shield », « honeypot » ou « leurre »."""
    text = source.read_text(encoding="utf-8").lower()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("#", '"""', "'''")) or "``" in line:
            continue
        if stripped.startswith(("writer.write", "response =", "_login_page")):
            for needle in ("honeypot", "leurre", "shield"):
                assert needle not in stripped


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"", ("", "")),
        (b"SSH-2.0-libssh-0.9.6", ("", "")),
        (b"root:123456", ("root", "123456")),
        (b"admin password", ("admin", "password")),
        (b"\xff\xfe\x00 garbage", ("", "")),
    ],
)
def test_extraction_identifiants_ssh(payload, expected):
    assert SSHDecoy.read_auth_attempt(payload) == expected


def test_analyse_http_extrait_methode_et_identifiants():
    request = (
        b"POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.0\r\n\r\n"
        b"username=admin&password=hunter2"
    )
    parsed = HTTPDecoy.parse_request(request)
    assert parsed["method"] == "POST"
    assert parsed["username"] == "admin"
    assert parsed["password"] == "hunter2"
    assert parsed["user_agent"] == "curl/8.0"


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x00\x01\x02", b"GARBAGE", b"GET", b"\xff" * 100, b"POST /x HTTP/1.1\r\n\r\n"],
)
def test_analyse_http_ne_leve_jamais(payload):
    assert isinstance(HTTPDecoy.parse_request(payload), dict)


def test_la_page_servie_ne_reinjecte_pas_la_saisie():
    """Un leurre vulnérable au XSS réfléchi serait à la fois ridicule et dangereux."""
    page = HTTPDecoy.serve_login_page(
        HTTPDecoy(port=80, ingest_url="http://x", ingest_token="t")
    ).decode()
    assert "<script>" not in page.replace("<script>alert", "")
    assert "value=" not in page


async def ftp_session(*packets: bytes) -> tuple[dict, bytes]:
    """Joue des paquets contre un vrai leurre FTP ; retourne l'événement émis et les réponses."""
    emitted: list[dict] = []
    received = asyncio.Event()

    def capture(request: httpx.Request) -> httpx.Response:
        emitted.append(json.loads(request.content))
        received.set()
        return httpx.Response(202)

    decoy = FTPDecoy(
        port=0,
        ingest_url="http://collector/api/v1/ingest",
        ingest_token="t",
        banner="220 (vsFTPd 3.0.5)",
        client=httpx.AsyncClient(transport=httpx.MockTransport(capture)),
    )
    await decoy.start()
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", decoy._server.sockets[0].getsockname()[1]
        )
        await reader.readline()  # bannière
        for packet in packets:
            writer.write(packet)
            await writer.drain()
            await asyncio.sleep(0.05)
        await asyncio.wait_for(received.wait(), timeout=5)
        replies = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
    finally:
        await decoy.stop()
    [event] = emitted
    return event, replies


async def test_ftp_user_et_pass_dans_un_meme_paquet():
    """#53 : un robot qui enchaîne USER et PASS ne doit pas perdre le mot de passe."""
    event, replies = await ftp_session(b"USER bob\r\nPASS secret\r\n")
    assert (event["username"], event["password"]) == ("bob", "secret")
    assert replies == b"331 Please specify the password.\r\n530 Login incorrect.\r\n"


async def test_ftp_user_et_pass_dans_deux_paquets():
    event, replies = await ftp_session(b"USER bob\r\n", b"PASS secret\r\n")
    assert (event["username"], event["password"]) == ("bob", "secret")
    assert replies.endswith(b"530 Login incorrect.\r\n")
