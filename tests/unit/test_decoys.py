"""Les leurres doivent analyser sans jamais interpréter, et ne jamais se trahir."""

from pathlib import Path

import pytest

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
