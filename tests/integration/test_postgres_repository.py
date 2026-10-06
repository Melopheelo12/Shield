"""Le collecteur branché sur PostgreSQL (S1-06) : écriture, relecture, agrégats, chaîne complète."""

import dataclasses
from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from shield.collector.api import app as api
from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.repositories import PostgresEventRepository
from shield.common.schema import EnrichmentStatus, NormalizedEvent, RawEvent

AGENT = DefenderAgent(engine=RuleEngine.from_file("rules/detection_rules.yaml"))
MAPPER = MitreMapper()


@pytest.fixture
async def repository(pg_engine):
    repo = PostgresEventRepository(engine=pg_engine)
    await repo.prepare(AGENT.engine.rules)
    return repo


async def capture(repository, *, session_id: UUID | None = None, **fields):
    """Le chemin d'ingestion de l'API, sans HTTP."""
    body = dict(
        service="ssh",
        source_ip="198.51.100.7",
        source_port=51515,
        dest_port=22,
        username="root",
        password="123456",
    )
    body.update(fields)
    raw = RawEvent(**body).truncated()
    counters = await repository.counters(raw)
    event = NormalizedEvent(
        **raw.model_dump(exclude={"payload"}),
        payload=raw.payload,
        session_id=session_id or uuid4(),
        technique_id=MAPPER.map(raw),
        enrichment_status=EnrichmentStatus.PARTIAL,
    )
    verdict = AGENT.evaluate(event, counters)
    event = event.model_copy(update={"threat_score": verdict.threat_score})
    await repository.save(event, verdict)
    return event, verdict


async def fetch_one(engine, sql: str, **params):
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).one()


async def test_un_evenement_ecrit_se_relit_a_l_identique(repository):
    event, _ = await capture(repository, payload=b"\x00\xffSSH-2.0-libssh\r\n" * 400)
    assert event.payload_truncated

    [stored] = await repository.query()
    assert stored.event_id == event.event_id
    assert stored.occurred_at == event.occurred_at
    assert stored.service == event.service
    assert stored.source_ip == event.source_ip
    assert (stored.username, stored.password) == ("root", "123456")
    assert stored.payload == event.payload
    assert stored.payload_truncated
    assert stored.session_id == event.session_id
    assert stored.technique_id == event.technique_id
    assert stored.threat_score == event.threat_score
    assert stored.enrichment_status == EnrichmentStatus.PARTIAL


async def test_le_verdict_relu_est_celui_de_l_agent(repository):
    event, verdict = await capture(repository)
    assert verdict.matches, "le jeu d'essai doit déclencher au moins une règle"

    stored = await repository.get_verdict(event.event_id)
    assert stored == verdict
    assert stored.is_consistent()


async def test_verdict_d_un_evenement_inconnu(repository):
    assert await repository.get_verdict(uuid4()) is None


async def test_l_evenement_atterrit_dans_sa_partition_mensuelle(repository, pg_engine):
    event, _ = await capture(repository)
    [partition] = await fetch_one(
        pg_engine,
        "SELECT tableoid::regclass::text FROM event WHERE event_uid = :uid",
        uid=event.event_id,
    )
    assert partition == event.occurred_at.strftime("event_%Y_%m")


async def test_les_partitions_des_mois_a_venir_sont_creees_d_avance(repository, pg_engine):
    """#62 : le 1er décembre, l'événement va dans sa partition, pas dans event_default."""
    await repository.maintain(today=date(2026, 11, 15))
    await repository.maintain(today=date(2026, 11, 16))  # idempotente

    for month in ("event_2026_11", "event_2026_12", "event_2027_01"):
        [exists] = await fetch_one(pg_engine, "SELECT to_regclass(:name) IS NOT NULL", name=month)
        assert exists, month

    event, _ = await capture(repository, occurred_at=datetime(2026, 12, 1, tzinfo=UTC))
    [partition] = await fetch_one(
        pg_engine,
        "SELECT tableoid::regclass::text FROM event WHERE event_uid = :uid",
        uid=event.event_id,
    )
    assert partition == "event_2026_12"


async def test_session_et_adresse_sont_agregees(repository, pg_engine):
    session_id = uuid4()
    first, _ = await capture(repository, session_id=session_id, username="guest", password="x")
    second, worst = await capture(repository, session_id=session_id)
    assert second.threat_score > first.threat_score

    count, score, profile = await fetch_one(
        pg_engine,
        "SELECT event_count, threat_score, attacker_profile FROM session WHERE id = :id",
        id=session_id,
    )
    assert (count, score, profile) == (2, worst.threat_score, worst.profile.value)

    [total] = await fetch_one(
        pg_engine, "SELECT total_events FROM ip_intel WHERE ip = '198.51.100.7'"
    )
    assert total == 2


async def test_les_compteurs_respectent_les_fenetres(repository):
    now = datetime.now(UTC)
    await capture(repository, occurred_at=now - timedelta(hours=2))
    await capture(repository, occurred_at=now - timedelta(minutes=1))
    await capture(repository, occurred_at=now - timedelta(minutes=1), username="", password="")
    await capture(repository, occurred_at=now - timedelta(minutes=1), service="ftp", dest_port=21)
    await capture(repository, source_ip="203.0.113.99")

    raw = RawEvent(
        service="http", source_ip="198.51.100.7", source_port=1, dest_port=80, occurred_at=now
    )
    assert await repository.counters(raw) == {
        "auth_attempts_by_ip": 2 + 1,  # ssh et ftp à 1 min, avec identifiants
        "distinct_services_by_ip": 3,  # ssh, ftp, et l'http courant
        "events_by_ip_24h": 4 + 1,
    }


async def test_les_statistiques(repository):
    await capture(repository)
    await capture(repository, username="admin")
    await capture(repository, source_ip="203.0.113.99", service="ftp", dest_port=21)
    await repository.record_rejected("service: invalide", b'{"service": "telnet"}')

    overview = await repository.overview()
    assert overview["events"] == 3
    assert overview["unique_ips"] == 2
    assert overview["sessions"] == 3
    assert overview["rejected"] == 1
    assert overview["max_threat_score"] > 0

    [top, other] = await repository.top_ips()
    assert (top["source_ip"], top["events"]) == ("198.51.100.7", 2)
    assert (other["source_ip"], other["events"]) == ("203.0.113.99", 1)

    credentials = await repository.top_credentials()
    assert credentials["usernames"][0] == {"value": "root", "count": 2}
    assert credentials["passwords"] == [{"value": "123456", "count": 3}]

    assert await repository.by_service() == [
        {"service": "ftp", "count": 1, "percentage": 33.3},
        {"service": "ssh", "count": 2, "percentage": 66.7},
    ]

    assert [e.service.value for e in await repository.query(service="ftp")] == ["ftp"]
    assert len(await repository.query(limit=2)) == 2


async def test_un_identifiant_hostile_ne_bloque_pas_l_ecriture(repository):
    await capture(repository, username="ro\x00ot", password="\x00")
    await repository.record_rejected("username: \x00", b"\x00")

    [stored] = await repository.query()
    assert stored.username == "ro�ot"
    assert stored.password == "�"
    assert (await repository.overview())["rejected"] == 1


async def test_prepare_est_idempotente_et_suit_le_fichier_de_regles(repository, pg_engine):
    rules = AGENT.engine.rules
    changed = [dataclasses.replace(rules[0], weight=rules[0].weight + 1, version=2), *rules[1:]]

    await repository.prepare(changed)

    count, weight, version = await fetch_one(
        pg_engine,
        "SELECT (SELECT count(*) FROM detection_rule), weight, version "
        "FROM detection_rule WHERE rule_key = :key",
        key=rules[0].id,
    )
    assert (count, weight, version) == (len(rules), rules[0].weight + 1, 2)


async def test_chaine_complete_ingestion_vers_verdict(repository):
    api.app.state.repository = repository
    headers = {"X-Ingest-Token": api.INGEST_TOKEN}
    try:
        async with AsyncClient(
            transport=ASGITransport(app=api.app), base_url="http://test"
        ) as client:
            body = dict(
                service="ssh",
                source_ip="192.0.2.44",
                source_port=40000,
                dest_port=22,
                username="root",
                password="toor",
            )
            ack = (await client.post("/api/v1/ingest", json=body, headers=headers)).json()

            verdict = (await client.get(f"/api/v1/events/{ack['event_id']}/verdict")).json()
            assert verdict["threat_score"] == ack["threat_score"] > 0
            assert sum(m["contribution"] for m in verdict["matches"]) == verdict["threat_score"]

            events = (await client.get("/api/v1/events")).json()
            assert [item["event_id"] for item in events["items"]] == [ack["event_id"]]

            rejected = await client.post(
                "/api/v1/ingest", json={**body, "dest_port": 70000}, headers=headers
            )
            assert rejected.status_code == 422
            overview = (await client.get("/api/v1/stats/overview")).json()
            assert (overview["events"], overview["rejected"]) == (1, 1)
    finally:
        del api.app.state.repository
