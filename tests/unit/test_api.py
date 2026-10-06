"""L'API du collecteur, sur l'entrepôt en mémoire : routes, authentification, rejets."""

import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector.api import app as api
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
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as http:
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


def test_le_stockage_se_choisit_par_variable_d_environnement(monkeypatch):
    monkeypatch.setenv("SHIELD_STORAGE", "memory")
    assert isinstance(build_repository(), InMemoryEventRepository)

    monkeypatch.setenv("SHIELD_STORAGE", "postgres")
    assert isinstance(build_repository(), PostgresEventRepository)

    monkeypatch.setenv("SHIELD_STORAGE", "sqlite")
    with pytest.raises(ValueError, match="SHIELD_STORAGE"):
        build_repository()
