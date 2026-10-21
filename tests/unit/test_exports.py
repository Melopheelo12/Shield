"""Export (S4-06), pseudonymisation et purge (S4-04), liste de blocage (S4-07)."""

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector import exports
from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.exports import csv_stream, json_stream, neutralize_formula, pseudonymize_ip
from shield.collector.repositories import InMemoryEventRepository
from shield.common.schema import NormalizedEvent, ServiceName, Verdict

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


async def store(repo, ip="203.0.113.42", score=0, at=NOW, username="root", password="toor"):
    event = NormalizedEvent(
        service=ServiceName.SSH,
        source_ip=ip_address(ip),
        source_port=1,
        dest_port=22,
        username=username,
        password=password,
        occurred_at=at,
        threat_score=score,
    )
    verdict = Verdict(
        event_id=event.event_id, session_id=None, threat_score=score, profile="indetermine"
    )
    await repo.save(event, verdict)
    return event


async def collect(stream) -> str:
    return "".join([chunk async for chunk in stream])


# --------------------------------------------------------------------------- pseudonymisation


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("203.0.113.42", "203.0.113.0"),
        ("10.0.0.255", "10.0.0.0"),
        ("2001:db8:abcd:12::1", "2001:db8:abcd::"),
    ],
)
def test_pseudonymisation_des_adresses(ip, expected):
    assert pseudonymize_ip(ip) == expected


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2", "@SUM(A1)", "\t=x", "\r=x"])
def test_les_formules_sont_neutralisees(value):
    assert neutralize_formula(value) == "'" + value


@pytest.mark.parametrize("value", ["root", "", 42, None, "a=b"])
def test_les_valeurs_ordinaires_sont_intactes(value):
    assert neutralize_formula(value) == value


# --------------------------------------------------------------------------- flux


async def test_export_csv_pseudonymise_sans_mot_de_passe():
    repo = InMemoryEventRepository()
    await store(repo, username='=HYPERLINK("http://x")', password="s3cret")

    async def fetch(cursor, limit):
        return await repo.export_page(None, None, cursor, limit)

    text = await collect(csv_stream(fetch, pseudonymize=True))
    [row] = list(csv.DictReader(io.StringIO(text)))
    assert row["source_ip"] == "203.0.113.0"
    assert "password" not in row
    assert "s3cret" not in text
    assert row["username"].startswith("'=")


async def test_export_json_complet_en_plusieurs_lots(monkeypatch):
    monkeypatch.setattr(exports, "EXPORT_BATCH_SIZE", 2)
    repo = InMemoryEventRepository()
    stored = [await store(repo, at=NOW + timedelta(seconds=i)) for i in range(5)]
    calls = []

    async def fetch(cursor, limit):
        calls.append(cursor)
        return await repo.export_page(None, None, cursor, limit)

    rows = json.loads(await collect(json_stream(fetch, pseudonymize=False)))
    assert [row["event_id"] for row in rows] == [str(e.event_id) for e in stored]
    assert rows[0]["password"] == "toor"
    assert len(calls) == 3, "5 événements, lots de 2 : trois pages"


async def test_export_vide_reste_valide():
    async def fetch(cursor, limit):
        return []

    assert json.loads(await collect(json_stream(fetch, pseudonymize=True))) == []
    assert (await collect(csv_stream(fetch, pseudonymize=True))).startswith("event_id,")


async def test_la_page_d_export_respecte_la_periode():
    repo = InMemoryEventRepository()
    await store(repo, at=NOW - timedelta(days=2))
    inside = await store(repo, at=NOW)
    await store(repo, at=NOW + timedelta(days=2))
    page = await repo.export_page(NOW - timedelta(hours=1), NOW + timedelta(hours=1), None, 10)
    assert [e.event_id for e in page] == [inside.event_id]


# --------------------------------------------------------------------------- purge


async def test_la_purge_supprime_ce_qui_depasse_la_conservation():
    repo = InMemoryEventRepository()
    old = await store(repo, at=NOW - timedelta(days=400))
    recent = await store(repo, at=NOW - timedelta(days=10))
    summary = await repo.purge(NOW - timedelta(days=365))
    assert summary == {"event": 1}
    assert [e.event_id for e in repo.events] == [recent.event_id]
    assert old.event_id not in repo.verdicts


# --------------------------------------------------------------------------- API


@pytest.fixture
async def client():
    api.app.state.repository = InMemoryEventRepository()
    token, _ = create_access_token("admin")
    async with AsyncClient(
        transport=ASGITransport(app=api.app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as http:
        yield http
    del api.app.state.repository


async def test_route_d_export(client):
    await store(api.app.state.repository, at=datetime.now(UTC))
    response = await client.get("/api/v1/export", params={"format": "csv", "pseudonymize": True})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "-pseudonymise.csv" in response.headers["content-disposition"]
    assert response.headers["x-shield-pseudonymized"] == "true", "US-47 : jamais silencieux"
    assert "203.0.113.0" in response.text and "toor" not in response.text


async def test_l_export_exige_un_jeton():
    api.app.state.repository = InMemoryEventRepository()
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://t") as http:
        assert (await http.get("/api/v1/export")).status_code == 401
    del api.app.state.repository


async def test_liste_de_blocage(client):
    repo = api.app.state.repository
    now = datetime.now(UTC)
    await store(repo, ip="198.51.100.1", score=90, at=now)
    await store(repo, ip="198.51.100.2", score=65, at=now)
    await store(repo, ip="198.51.100.3", score=10, at=now)
    await store(repo, ip="198.51.100.4", score=99, at=now - timedelta(days=30))

    response = await client.get("/api/v1/blocklist")
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == "198.51.100.1\n198.51.100.2\n"


async def test_un_pare_feu_utilise_son_propre_jeton(monkeypatch):
    monkeypatch.setenv("BLOCKLIST_TOKEN", "jeton-pare-feu")
    api.app.state.repository = InMemoryEventRepository()
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://t") as http:
        ok = await http.get("/api/v1/blocklist", headers={"X-Blocklist-Token": "jeton-pare-feu"})
        bad = await http.get("/api/v1/blocklist", headers={"X-Blocklist-Token": "faux"})
        none = await http.get("/api/v1/blocklist")
    del api.app.state.repository
    assert (ok.status_code, bad.status_code, none.status_code) == (200, 401, 401)
