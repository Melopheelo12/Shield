"""Temps réel (S3-02) : un événement ingéré part vers les écrans, sans jamais freiner l'ingestion."""

import asyncio

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.realtime import QUEUE_SIZE, Broadcaster, next_frame


async def test_chaque_abonne_recoit_chaque_trame():
    broadcaster = Broadcaster()
    async with broadcaster.subscribe() as first, broadcaster.subscribe() as second:
        await broadcaster.publish({"type": "event", "data": 1})
        assert first.get_nowait() == second.get_nowait() == {"type": "event", "data": 1}
    assert broadcaster.subscribers == 0, "un client parti est désabonné"


async def test_un_client_lent_perd_ses_plus_vieilles_trames_sans_bloquer():
    broadcaster = Broadcaster()
    async with broadcaster.subscribe() as queue:
        for index in range(QUEUE_SIZE + 10):
            await broadcaster.publish({"type": "event", "data": index})
        assert queue.qsize() == QUEUE_SIZE
        assert queue.get_nowait()["data"] == 10


class BrokenRedis:
    async def publish(self, channel, message):
        raise ConnectionError("redis absent")

    async def aclose(self):
        raise ConnectionError("redis absent")


async def test_redis_absent_n_empeche_pas_la_diffusion():
    broadcaster = Broadcaster(redis=BrokenRedis())
    async with broadcaster.subscribe() as queue:
        await broadcaster.publish({"type": "event", "data": "x"})
        assert queue.get_nowait()["data"] == "x"
    await broadcaster.close()


async def test_un_ping_quand_rien_n_arrive():
    queue = asyncio.Queue()
    assert await next_frame(queue, timeout=0.01) == {"type": "ping"}


@pytest.fixture
def http(monkeypatch):
    """``with`` : une seule boucle pour l'ingestion et le WebSocket, cycle de vie compris."""
    monkeypatch.setenv("SHIELD_STORAGE", "memory")
    monkeypatch.setenv("WATCH_ENABLED", "false")
    with TestClient(api.app) as client:
        yield client
    del api.app.state.repository


def test_un_evenement_ingere_arrive_sur_le_websocket(http):
    token, _ = create_access_token("admin")
    with http.websocket_connect(f"/ws/events?token={token}") as ws:
        ack = http.post(
            "/api/v1/ingest",
            json={"service": "ssh", "source_ip": "192.0.2.5", "source_port": 1, "dest_port": 22},
            headers={"X-Ingest-Token": api.INGEST_TOKEN},
        ).json()
        frame = ws.receive_json()
    assert frame["type"] == "event"
    assert frame["data"]["event_id"] == ack["event_id"]
    assert frame["data"]["threat_score"] == ack["threat_score"]


@pytest.mark.parametrize("query", ["", "?token=faux"])
def test_le_websocket_exige_un_jeton(http, query):
    with pytest.raises(WebSocketDisconnect) as exc:
        with http.websocket_connect(f"/ws/events{query}") as ws:
            ws.receive_json()
    assert exc.value.code == 1008
