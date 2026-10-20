"""L'API du collecteur, sur l'entrepôt en mémoire : routes, authentification, rejets."""

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.enrichment.geoip import GeoInfo
from shield.collector.enrichment.reputation import InMemoryReputationCache, ReputationEnricher
from shield.collector.repositories import (
    InMemoryEventRepository,
    PostgresEventRepository,
    build_repository,
)

HEADERS = {"X-Ingest-Token": api.INGEST_TOKEN}


@pytest.fixture
def repository():
    repo = InMemoryEventRepository()
    api.app.state.repository = repo
    yield repo
    del api.app.state.repository


@pytest.fixture
async def client(repository):
    """Un exploitant authentifié : les routes de consultation exigent un jeton (US-19)."""
    token, _ = create_access_token("admin")
    async with AsyncClient(
        transport=ASGITransport(app=api.app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as http:
        yield http


def ssh_attempt(**overrides) -> dict:
    body = dict(
        service="ssh",
        source_ip="192.0.2.10",
        source_port=40000,
        dest_port=22,
        username="root",
        password="123456",
    )
    body.update(overrides)
    return body


async def test_un_evenement_ingere_est_consultable_avec_son_verdict(client):
    response = await client.post("/api/v1/ingest", json=ssh_attempt(), headers=HEADERS)
    assert response.status_code == 202
    ack = response.json()
    assert ack["threat_score"] > 0

    events = (await client.get("/api/v1/events")).json()
    assert events["count"] == 1
    assert events["items"][0]["event_id"] == ack["event_id"]

    verdict = (await client.get(f"/api/v1/events/{ack['event_id']}/verdict")).json()
    assert verdict["threat_score"] == ack["threat_score"]
    assert sum(match["contribution"] for match in verdict["matches"]) == verdict["threat_score"]

    overview = (await client.get("/api/v1/stats/overview")).json()
    assert overview["events"] == 1
    assert overview["rejected"] == 0


async def test_sans_jeton_rien_n_est_ecrit_meme_en_rejet(client, repository):
    response = await client.post("/api/v1/ingest", json={"service": "telnet"})
    assert response.status_code == 401
    assert not repository.events
    assert not repository.rejected


@pytest.mark.parametrize("token", [None, "mauvais-jeton"])
async def test_sans_jeton_un_json_illisible_n_est_pas_trace(client, repository, token):
    """#63 : FastAPI décode le corps avant de vérifier le jeton."""
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Ingest-Token"] = token
    response = await client.post("/api/v1/ingest", content=b'{"service":', headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid ingest token"}
    assert not repository.rejected


async def test_un_evenement_malforme_est_rejete_mais_trace(client, repository):
    response = await client.post(
        "/api/v1/ingest", json=ssh_attempt(service="telnet"), headers=HEADERS
    )
    assert response.status_code == 422
    assert not repository.events
    [(reason, raw_body)] = repository.rejected
    assert "service" in reason
    assert b"telnet" in raw_body
    assert (await client.get("/api/v1/stats/overview")).json()["rejected"] == 1


async def test_un_json_illisible_est_trace_aussi(client, repository):
    response = await client.post(
        "/api/v1/ingest",
        content=b"{pas du json",
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert len(repository.rejected) == 1


async def test_verdict_d_un_evenement_inconnu(client):
    response = await client.get("/api/v1/events/00000000-0000-4000-8000-000000000000/verdict")
    assert response.status_code == 404


async def test_les_statistiques_suivent_les_ingestions(client):
    for user in ("root", "root", "admin"):
        await client.post("/api/v1/ingest", json=ssh_attempt(username=user), headers=HEADERS)
    await client.post(
        "/api/v1/ingest", json=ssh_attempt(service="ftp", dest_port=21), headers=HEADERS
    )

    credentials = (await client.get("/api/v1/stats/top-credentials")).json()
    assert credentials["usernames"][0] == {"value": "root", "count": 3}

    by_service = (await client.get("/api/v1/stats/by-service")).json()["items"]
    assert {item["service"]: item["count"] for item in by_service} == {"ftp": 1, "ssh": 3}

    top = (await client.get("/api/v1/stats/top-ips")).json()["items"]
    assert top[0]["source_ip"] == "192.0.2.10"
    assert top[0]["events"] == 4


async def test_l_ingestion_geolocalise_avant_le_verdict(client, repository, monkeypatch):
    """S2-01 : GeoLite2 est local, il passe avant l'agent défenseur."""
    seen = []

    class StubGeoIp:
        def lookup(self, ip):
            seen.append(str(ip))
            return GeoInfo(country_code="NL", asn=64500, as_org="Exemple BV")

    monkeypatch.setattr(api, "geoip", StubGeoIp())
    response = await client.post(
        "/api/v1/ingest", json=ssh_attempt(source_ip="203.0.113.5"), headers=HEADERS
    )
    assert response.status_code == 202
    assert seen == ["203.0.113.5"]

    [item] = (await client.get("/api/v1/events", params={"country": "NL"})).json()["items"]
    assert (item["country_code"], item["asn"], item["as_org"]) == ("NL", 64500, "Exemple BV")


async def test_une_reputation_en_cache_compte_des_l_ingestion(client, monkeypatch):
    """S2-02 : une adresse déjà connue déclenche R-003 / R-004 sans appel réseau."""
    cache = InMemoryReputationCache()
    await cache.set("8.8.8.8", 90)
    monkeypatch.setattr(api, "reputation", ReputationEnricher(cache))

    acks = {}
    for ip in ("8.8.8.8", "9.9.9.9"):
        body = ssh_attempt(source_ip=ip)
        acks[ip] = (await client.post("/api/v1/ingest", json=body, headers=HEADERS)).json()
    known, unknown = acks["8.8.8.8"], acks["9.9.9.9"]

    verdict = (await client.get(f"/api/v1/events/{known['event_id']}/verdict")).json()
    assert {"R-003", "R-004"} <= {match["rule_id"] for match in verdict["matches"]}
    assert known["threat_score"] > unknown["threat_score"]

    statuses = {
        item["source_ip"]: item["enrichment_status"]
        for item in (await client.get("/api/v1/events")).json()["items"]
    }
    assert statuses == {"8.8.8.8": "done", "9.9.9.9": "partial"}


async def test_detail_de_session_avec_ses_regles(client):
    """S3-04 : la session porte son pire score, et ses règles agrégées l'expliquent."""
    acks = []
    for password in ("123456", "admin", "unguessable-9f3a"):
        body = ssh_attempt(password=password)
        acks.append((await client.post("/api/v1/ingest", json=body, headers=HEADERS)).json())
    session_id = acks[0]["session_id"]
    assert {ack["session_id"] for ack in acks} == {session_id}

    detail = (await client.get(f"/api/v1/sessions/{session_id}")).json()
    assert detail["event_count"] == 3 and len(detail["events"]) == 3
    assert detail["threat_score"] == max(ack["threat_score"] for ack in acks)
    assert detail["events"][0]["event_id"] == acks[-1]["event_id"], "le plus récent d'abord"

    rules = {rule["rule_id"]: rule for rule in detail["rules"]}
    assert rules["R-002"]["matches"] == 3, "root visé à chaque tentative"
    assert rules["R-001"]["matches"] == 2, "deux couples par défaut sur trois"
    contributions = [rule["total_contribution"] for rule in detail["rules"]]
    assert contributions == sorted(contributions, reverse=True)


async def test_session_inconnue(client):
    response = await client.get("/api/v1/sessions/00000000-0000-4000-8000-000000000000")
    assert response.status_code == 404


async def test_chronologie_et_pays(client, monkeypatch):
    class StubGeoIp:
        def lookup(self, ip):
            return GeoInfo(country_code="FR" if str(ip).endswith(".1") else None)

    monkeypatch.setattr(api, "geoip", StubGeoIp())
    for ip in ("192.0.2.1", "198.51.100.1", "192.0.2.2"):
        await client.post("/api/v1/ingest", json=ssh_attempt(source_ip=ip), headers=HEADERS)

    timeline = (await client.get("/api/v1/stats/timeline", params={"hours": 1})).json()
    assert sum(item["events"] for item in timeline["items"]) == 3
    assert timeline["bucket_minutes"] == 60

    countries = (await client.get("/api/v1/stats/by-country")).json()["items"]
    assert countries == [
        {"country_code": "FR", "events": 2, "unique_ips": 2},
        {"country_code": None, "events": 1, "unique_ips": 1},
    ]


async def test_chronologie_trop_fine_refusee(client):
    params = {"hours": 720, "bucket_minutes": 1}
    assert (await client.get("/api/v1/stats/timeline", params=params)).status_code == 422


def test_le_stockage_se_choisit_par_variable_d_environnement(monkeypatch):
    monkeypatch.setenv("SHIELD_STORAGE", "memory")
    assert isinstance(build_repository(), InMemoryEventRepository)

    monkeypatch.setenv("SHIELD_STORAGE", "postgres")
    assert isinstance(build_repository(), PostgresEventRepository)

    monkeypatch.setenv("SHIELD_STORAGE", "sqlite")
    with pytest.raises(ValueError, match="SHIELD_STORAGE"):
        build_repository()


async def test_la_maintenance_survit_a_un_echec(repository, monkeypatch):
    calls = []

    async def maintain():
        calls.append(None)
        if len(calls) == 1:
            raise RuntimeError("base indisponible")

    monkeypatch.setattr(repository, "maintain", maintain)
    task = asyncio.create_task(api.run_periodically(repository.maintain, interval=0))
    while len(calls) < 3:
        await asyncio.sleep(0)
    task.cancel()
    assert len(calls) >= 3
