"""Les leurres doivent analyser sans jamais interpréter, et ne jamais se trahir."""

import asyncio
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from shield.common.schema import MAX_PAYLOAD_BYTES
from shield.decoys.ftp import FTPDecoy
from shield.decoys.http import HTTPDecoy
from shield.decoys.site import TRAP_PASSWORD
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


def http_decoy(**kwargs) -> HTTPDecoy:
    return HTTPDecoy(port=80, ingest_url="http://x", ingest_token="t", **kwargs)


MARKER = "zq7MARQUEURzq7"


@pytest.mark.parametrize(
    "method,target",
    [
        ("GET", f"/?s=<script>{MARKER}</script>"),
        ("POST", f"/wp-login.php?redirect_to={MARKER}"),
        ("GET", f"/{MARKER}"),
        ("GET", f"/wp-admin/{MARKER}"),
        ("POST", f"/xmlrpc.php?{MARKER}"),
        ("GET", f"/?author={MARKER}"),
    ],
)
def test_aucune_saisie_n_est_reinjectee(method, target):
    """Un leurre vulnérable au XSS réfléchi serait à la fois ridicule et dangereux."""
    assert MARKER.encode() not in http_decoy().render(method, target)


def test_la_page_de_connexion_ne_contient_aucun_script():
    page = http_decoy().serve_login_page().decode()
    assert "<script" not in page.lower()


def status_of(response: bytes) -> str:
    return response.split(b"\r\n", 1)[0].decode()


@pytest.mark.parametrize(
    "method,target,status,needle",
    [
        ("GET", "/", "200 OK", b'content="WordPress 5.8.3"'),
        ("GET", "/index.php", "200 OK", b"Menuiserie des Tilleuls"),
        ("GET", "/wp-login.php", "200 OK", b'name="log"'),
        ("POST", "/wp-login.php", "200 OK", b"login_error"),
        ("GET", "/wp-admin/", "302 Found", b"Location: /wp-login.php?redirect_to="),
        ("GET", "/xmlrpc.php", "405 Method Not Allowed", b"POST requests only"),
        ("POST", "/xmlrpc.php", "200 OK", b"<int>403</int>"),
        ("GET", "/readme.html", "200 OK", b"Version 5.8.3"),
        ("GET", "/robots.txt", "200 OK", b"Disallow: /wp-admin/"),
        ("GET", "/?author=1", "301 Moved Permanently", b"Location: /author/atelier/"),
        ("GET", "/wp-json/wp/v2/users", "200 OK", b'"slug":"atelier"'),
        ("GET", "/wp-json/", "200 OK", b'"namespaces"'),
        ("GET", "/.env", "404 Not Found", b"Rien de trouv"),
        ("GET", "/phpmyadmin/", "404 Not Found", b"error404"),
        ("GET", "/nimporte-quoi", "404 Not Found", b"error404"),
    ],
)
def test_le_site_repond_comme_wordpress(method, target, status, needle):
    """Un serveur qui répond 200 et la même page partout est la signature d'un honeypot."""
    response = http_decoy().render(method, target)
    assert status_of(response) == f"HTTP/1.1 {status}"
    assert needle in response


def test_en_tetes_et_signatures_de_version():
    response = http_decoy().render("GET", "/")
    head = response.split(b"\r\n\r\n", 1)[0].decode()
    assert "Server: nginx/1.18.0" in head
    assert "X-Powered-By: PHP/7.4.33" in head
    length = int(
        next(line for line in head.splitlines() if line.startswith("Content-Length")).split()[1]
    )
    assert length == len(response.split(b"\r\n\r\n", 1)[1])
    assert "Server: Apache" in http_decoy(banner="Apache").render("GET", "/").decode()


def test_head_n_envoie_pas_de_corps():
    response = http_decoy().render("HEAD", "/")
    assert response.endswith(b"\r\n\r\n")
    assert b"Content-Length: 0" not in response


def test_le_nom_du_site_est_configurable_et_echappe(monkeypatch):
    monkeypatch.setenv("DECOY_HTTP_SITE_NAME", "Atelier <b>Test</b>")
    page = http_decoy().render("GET", "/").decode()
    assert "Atelier &lt;b&gt;Test&lt;/b&gt;" in page
    assert "<b>Test</b>" not in page


@pytest.mark.parametrize(
    "method,target",
    [(m, t) for m in ("GET", "POST", "HEAD") for t in ("/", "/wp-login.php", "/x", "/xmlrpc.php")],
)
def test_aucune_reponse_ne_trahit_le_leurre(method, target):
    """Le test statique ci-dessus lit le code ; celui-ci lit ce qui part réellement."""
    response = http_decoy().render(method, target).lower()
    for needle in (b"honeypot", b"leurre", b"shield", b"decoy"):
        assert needle not in response


@pytest.mark.parametrize(
    "request_bytes,expected",
    [
        (
            b"POST /wp-login.php HTTP/1.1\r\n\r\nlog=admin&pwd=Passw0rd%21&wp-submit=Se+connecter",
            ("admin", "Passw0rd!"),
        ),
        (b"POST /login HTTP/1.1\r\n\r\nusername=root&password=toor", ("root", "toor")),
        (
            b'POST /xmlrpc.php HTTP/1.1\r\n\r\n<?xml version="1.0"?><methodCall>'
            b"<methodName>wp.getUsersBlogs</methodName><params>"
            b"<param><value><string>editor</string></value></param>"
            b"<param><value><string>123456</string></value></param></params></methodCall>",
            ("editor", "123456"),
        ),
        (
            b"GET /wp-admin/ HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n",
            ("admin", "secret"),
        ),
        (b"GET /wp-admin/ HTTP/1.1\r\nAuthorization: Basic !!!\r\n\r\n", ("", "")),
        (b'POST /xmlrpc.php HTTP/1.1\r\n\r\n<?xml version="1.0"?><methodCall/>', ("", "")),
    ],
)
def test_identifiants_wordpress_xmlrpc_et_basic(request_bytes, expected):
    parsed = HTTPDecoy.parse_request(request_bytes)
    assert (parsed.get("username", ""), parsed.get("password", "")) == expected


# --------------------------------------------------------------------------- faux système de fichiers (US-50)


@pytest.mark.parametrize(
    "target,status,needle",
    [
        ("/wp-config.php.bak", "200 OK", f"'DB_PASSWORD', '{TRAP_PASSWORD}' );".encode()),
        ("/backup", "301 Moved Permanently", b"Location: /backup/"),
        ("/backup/", "200 OK", b'<h1>Index of /backup/</h1><hr><pre><a href="../">../</a>'),
        ("/backup/wordpress-2023-11-04.sql.gz", "403 Forbidden", b"<h1>403 Forbidden</h1>"),
        ("/backup/uploads-2023-11-04.tar.gz", "403 Forbidden", b"nginx/1.18.0</center>"),
        ("/backup/autre.sql.gz", "404 Not Found", b"error404"),
        ("/wp-content/uploads", "301 Moved Permanently", b"Location: /wp-content/uploads/"),
        ("/wp-content/uploads/", "200 OK", b'<a href="2023/">2023/</a>'),
        (
            "/wp-content/uploads/2022",
            "301 Moved Permanently",
            b"Location: /wp-content/uploads/2022/",
        ),
        ("/wp-content/uploads/2022/", "403 Forbidden", b"<h1>403 Forbidden</h1>"),
        ("/wp-content/uploads/2019/", "404 Not Found", b"error404"),
        ("/wp-config.php", "404 Not Found", b"error404"),
    ],
)
def test_le_faux_systeme_de_fichiers_repond_comme_nginx(target, status, needle):
    response = http_decoy().render("GET", target)
    assert status_of(response) == f"HTTP/1.1 {status}"
    assert needle in response


def test_le_listing_a_les_colonnes_de_l_autoindex_de_nginx():
    body = http_decoy().render("GET", "/backup/").split(b"\r\n\r\n", 1)[1].decode()
    line = next(row for row in body.split("\r\n") if "wordpress-2023" in row)
    name = "wordpress-2023-11-04.sql.gz"
    # Nom sur 50 colonnes, une espace, la date, puis la taille alignée à droite sur 19.
    assert (
        line
        == f'<a href="{name}">{name}</a>{" " * (50 - len(name))} 04-Nov-2023 02:15 {4821307:>19}'
    )


@pytest.mark.parametrize(
    "target", ["/wp-config.php.bak", "/backup/", "/backup", "/wp-content/uploads/2022/"]
)
def test_nginx_sert_ces_pages_sans_php(target):
    """Un listing ou une 403 « propulsés par PHP » se trahiraient."""
    head = http_decoy().render("GET", target).split(b"\r\n\r\n", 1)[0]
    assert b"X-Powered-By" not in head
    assert b"api.w.org" not in head


@pytest.mark.parametrize(
    "target",
    [
        f"/backup/{MARKER}",
        f"/backup/{MARKER}/",
        f"/wp-content/uploads/{MARKER}/",
        f"/backup/?{MARKER}",
        f"/wp-config.php.bak?{MARKER}",
    ],
)
def test_le_faux_systeme_de_fichiers_ne_reinjecte_rien(target):
    for method in ("GET", "HEAD", "POST"):
        assert MARKER.encode() not in http_decoy().render(method, target)


def test_le_faux_wp_config_est_fixe_et_ne_trahit_rien():
    first = http_decoy().render("GET", "/wp-config.php.bak").split(b"\r\n\r\n", 1)[1]
    assert first == http_decoy().render("GET", "/wp-config.php.bak").split(b"\r\n\r\n", 1)[1]
    text = first.decode()
    assert text.count("define( '") == 16, "base (6), les 8 clés, WP_DEBUG et ABSPATH"
    for needle in ("honeypot", "leurre", "shield", "decoy", "python"):
        assert needle not in text.lower()


async def test_une_vraie_connexion_au_leurre_http():
    """De bout en bout : requête TCP réelle, réponse WordPress, événement émis."""
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
        client=httpx.AsyncClient(transport=httpx.MockTransport(capture)),
    )
    await decoy.start()
    try:
        port = decoy._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\nlog=admin&pwd=admin")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        await asyncio.wait_for(received.wait(), timeout=5)
        writer.close()
    finally:
        await decoy.stop()
    assert status_of(response) == "HTTP/1.1 200 OK"
    assert b"login_error" in response
    [event] = emitted
    assert (event["service"], event["username"], event["password"]) == ("http", "admin", "admin")


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


class _Peer:
    """Le strict nécessaire d'un ``StreamWriter`` pour ``build_raw_event``."""

    def get_extra_info(self, name):
        return ("203.0.113.5", 40000) if name == "peername" else None


def test_le_leurre_calcule_l_empreinte_sur_tout_ce_qu_il_a_lu():
    """US-06 : seul le leurre voit la charge entière, au-delà des 4 Ko transmis."""
    payload = bytes(range(256)) * 64  # 16 Kio
    event = SSHDecoy(port=22, ingest_url="http://x", ingest_token="t").build_raw_event(
        writer=_Peer(), payload=payload
    )
    assert len(event.payload) == MAX_PAYLOAD_BYTES
    assert event.payload_sha256 == hashlib.sha256(payload).hexdigest()
