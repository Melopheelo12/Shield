"""Authentification du tableau de bord (S3-01) : jeton obligatoire, force brute ralentie."""

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector.api import app as api
from shield.collector.api import auth
from shield.collector.repositories import InMemoryEventRepository

PROTECTED = [
    "/api/v1/events",
    "/api/v1/events/00000000-0000-4000-8000-000000000000/verdict",
    "/api/v1/rules",
    "/api/v1/stats/overview",
    "/api/v1/stats/top-ips",
    "/api/v1/stats/top-credentials",
    "/api/v1/stats/by-service",
    "/api/v1/stats/timeline",
    "/api/v1/stats/by-country",
    "/api/v1/sessions/00000000-0000-4000-8000-000000000000",
]


class Clock:
    def __init__(self):
        self.now = 10_000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def admin(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "exploitant")
    monkeypatch.setenv("ADMIN_PASSWORD", "un-vrai-mot-de-passe")
    monkeypatch.setenv("JWT_SECRET", "secret-de-test-" + "x" * 64)
    monkeypatch.setattr(auth, "throttle", auth.LoginThrottle())


@pytest.fixture
async def client():
    api.app.state.repository = InMemoryEventRepository()
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as http:
        yield http
    del api.app.state.repository


async def login(client, password="un-vrai-mot-de-passe", ip="198.51.100.1"):
    return await client.post(
        "/api/v1/auth/login",
        json={"username": "exploitant", "password": password},
        headers={"X-Real-IP": ip},
    )


@pytest.mark.parametrize("path", PROTECTED)
async def test_sans_jeton_aucune_donnee(client, path):
    response = await client.get(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_les_sondes_restent_publiques(client):
    assert (await client.get("/api/v1/health")).status_code == 200


async def test_connexion_puis_consultation(client):
    response = await login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 30 * 60

    headers = {"Authorization": f"Bearer {body['access_token']}"}
    assert (await client.get("/api/v1/stats/overview", headers=headers)).status_code == 200
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.json() == {"username": "exploitant"}


def unsigned_token() -> str:
    """Jeton ``alg=none`` forgé à l'exécution : aucun secret littéral dans le dépôt."""

    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part({'sub': 'admin', 'exp': 4_102_444_800})}."


def other_algorithm_token() -> str:
    """Bon secret, mauvais algorithme : seul HS256 est accepté."""
    return pyjwt.encode(
        {"sub": "admin", "exp": 4_102_444_800}, auth._jwt_secret(), algorithm="HS512"
    )


@pytest.mark.parametrize(
    "make_token",
    [lambda: "pas-un-jeton", unsigned_token, other_algorithm_token],
    ids=["illisible", "alg-none", "autre-algorithme"],
)
async def test_un_jeton_invalide_est_refuse(client, make_token):
    token = make_token()
    response = await client.get("/api/v1/events", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


async def test_un_jeton_expire_est_refuse(client):
    token, _ = auth.create_access_token("exploitant", now=datetime.now(UTC) - timedelta(hours=1))
    response = await client.get("/api/v1/events", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


async def test_un_jeton_signe_avec_un_autre_secret_est_refuse(client, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "autre-secret-" + "y" * 32)
    token, _ = auth.create_access_token("exploitant")
    monkeypatch.setenv("JWT_SECRET", "secret-de-test-" + "x" * 32)
    assert auth.decode_access_token(token) is None


async def test_mauvais_mot_de_passe(client):
    response = await login(client, password="123456")
    assert response.status_code == 401
    assert "access_token" not in response.json()


async def test_sans_mot_de_passe_configure_personne_n_entre(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "")
    assert (await login(client, password="")).status_code == 401


async def test_cinq_echecs_ralentissent_meme_le_bon_mot_de_passe(client):
    for _ in range(auth.MAX_FAILURES):
        assert (await login(client, password="faux")).status_code == 401

    blocked = await login(client)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0

    other_ip = await login(client, ip="198.51.100.2")
    assert other_ip.status_code == 200, "le ralentissement vise l'adresse, pas le compte"


def test_le_delai_double_a_chaque_echec_puis_expire():
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock)
    for _ in range(auth.MAX_FAILURES - 1):
        throttle.failure("a")
    assert throttle.retry_after("a") == 0

    throttle.failure("a")
    assert throttle.retry_after("a") == auth.FIRST_DELAY_SECONDS
    clock.now += auth.FIRST_DELAY_SECONDS
    assert throttle.retry_after("a") == 0

    throttle.failure("a")
    assert throttle.retry_after("a") == 2 * auth.FIRST_DELAY_SECONDS

    clock.now += auth.FAILURE_WINDOW_SECONDS + 1
    assert throttle.retry_after("a") == 0, "les échecs anciens sont oubliés"


def test_un_succes_efface_les_echecs():
    throttle = auth.LoginThrottle(clock=Clock())
    for _ in range(auth.MAX_FAILURES):
        throttle.failure("a")
    throttle.success("a")
    assert throttle.retry_after("a") == 0


@pytest.mark.parametrize("weak", ["JWT_SECRET", "ADMIN_PASSWORD", "INGEST_TOKEN"])
def test_la_production_refuse_les_secrets_d_exemple(monkeypatch, weak):
    monkeypatch.setenv("SHIELD_ENV", "prod")
    monkeypatch.setenv("JWT_SECRET", "s" * 40)
    monkeypatch.setenv("ADMIN_PASSWORD", "solide")
    monkeypatch.setenv("INGEST_TOKEN", "solide")
    auth.check_production_secrets()

    monkeypatch.setenv(weak, "change-me-quelque-chose-de-tres-long-pour-le-secret")
    with pytest.raises(RuntimeError):
        auth.check_production_secrets()


def test_la_production_refuse_un_secret_jwt_court(monkeypatch):
    monkeypatch.setenv("SHIELD_ENV", "prod")
    monkeypatch.setenv("JWT_SECRET", "court")
    monkeypatch.setenv("ADMIN_PASSWORD", "solide")
    monkeypatch.setenv("INGEST_TOKEN", "solide")
    with pytest.raises(RuntimeError):
        auth.check_production_secrets()
