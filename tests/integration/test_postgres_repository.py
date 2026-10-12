"""Le collecteur branché sur PostgreSQL (S1-06) : écriture, relecture, agrégats, chaîne complète."""

import csv
import dataclasses
import gzip
import hashlib
import json
from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.ingest.session_tracker import SessionTracker
from shield.collector.repositories import PostgresEventRepository
from shield.common.schema import EnrichmentStatus, NormalizedEvent, RawEvent

AGENT = DefenderAgent(engine=RuleEngine.from_file("rules/detection_rules.yaml"))
MAPPER = MitreMapper()


@pytest.fixture
async def repository(pg_engine):
    repo = PostgresEventRepository(engine=pg_engine)
    await repo.prepare(AGENT.engine.rules)
    return repo


async def capture(repository, *, session_id: UUID | None = None, geo: dict | None = None, **fields):
    """Le chemin d'ingestion de l'API, sans HTTP. ``geo`` tient lieu de GeoLite2."""
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
        **(geo or {}),
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
    assert stored.payload_sha256 == event.payload_sha256 is not None
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


async def test_la_geolocalisation_est_conservee_et_jamais_effacee(repository, pg_engine):
    """S2-01 : une base GeoLite2 plus récente corrige ; une base absente n'efface rien."""
    await capture(repository, geo={"country_code": "NL", "asn": 64500, "as_org": "Ancien\x00"})
    await capture(repository, geo={"country_code": "DE", "asn": 64501, "as_org": "Nouveau"})
    await capture(repository)  # GeoLite2 indisponible pour cet événement

    row = await fetch_one(
        pg_engine, "SELECT country_code, asn, as_org FROM ip_intel WHERE ip = '198.51.100.7'"
    )
    assert tuple(row) == ("DE", 64501, "Nouveau")

    [stored] = await repository.query(country="DE", limit=1)
    assert (stored.country_code, stored.asn, stored.as_org) == ("DE", 64501, "Nouveau")


async def test_la_reputation_differee_est_reprise_puis_close(repository, pg_engine):
    """S2-03 / S2-05 : les adresses en attente sortent, la réputation les clôt."""
    now = datetime.now(UTC)
    await capture(repository, occurred_at=now - timedelta(minutes=5))
    await capture(repository, source_ip="203.0.113.99", occurred_at=now)

    assert await repository.pending_reputation(10) == ["203.0.113.99", "198.51.100.7"]
    assert await repository.pending_reputation(1) == ["203.0.113.99"]

    await repository.apply_reputation("198.51.100.7", 91)
    assert await repository.pending_reputation(10) == ["203.0.113.99"]

    score, checked_at = await fetch_one(
        pg_engine,
        "SELECT reputation_score, reputation_checked_at FROM ip_intel WHERE ip = '198.51.100.7'",
    )
    assert score == 91 and checked_at is not None

    [stored] = [e for e in await repository.query() if str(e.source_ip) == "198.51.100.7"]
    assert stored.reputation_score == 91
    assert stored.enrichment_status == EnrichmentStatus.DONE


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


async def test_detail_de_session(repository):
    """S3-04 : les règles d'une session sont agrégées, la plus lourde d'abord."""
    session_id = uuid4()
    await capture(repository, session_id=session_id)
    _, worst = await capture(repository, session_id=session_id, password="toor")
    await capture(repository)  # autre session, même adresse

    detail = await repository.session_detail(session_id)
    assert detail["event_count"] == 2 and len(detail["events"]) == 2
    assert detail["threat_score"] == worst.threat_score
    rules = {rule["rule_id"]: rule for rule in detail["rules"]}
    assert rules["R-002"]["matches"] == 2
    contributions = [rule["total_contribution"] for rule in detail["rules"]]
    assert contributions == sorted(contributions, reverse=True)
    assert await repository.session_detail(uuid4()) is None


async def test_chronologie_et_pays(repository):
    base = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    await repository.maintain(today=base.date())
    await capture(repository, occurred_at=base + timedelta(minutes=5), geo={"country_code": "FR"})
    await capture(repository, occurred_at=base + timedelta(minutes=50))
    await capture(repository, source_ip="203.0.113.99", occurred_at=base + timedelta(minutes=70))

    timeline = await repository.timeline(base, timedelta(hours=1))
    assert [(item["bucket"][:16], item["events"]) for item in timeline] == [
        ("2026-10-12T10:00", 2),
        ("2026-10-12T11:00", 1),
    ]
    assert await repository.by_country() == [
        {"country_code": "FR", "events": 2, "unique_ips": 1},
        {"country_code": None, "events": 1, "unique_ips": 1},
    ]


async def test_export_par_curseur_et_liste_de_blocage(repository):
    now = datetime.now(UTC)
    stored = [
        (await capture(repository, occurred_at=now - timedelta(seconds=10 - i)))[0]
        for i in range(5)
    ]
    first = await repository.export_page(None, None, None, 2)
    cursor = (first[-1].occurred_at, first[-1].event_id)
    rest = await repository.export_page(None, None, cursor, 10)
    assert [e.event_id for e in first + rest] == [e.event_id for e in stored]

    await capture(repository, source_ip="203.0.113.99", username="", password="")
    hostile = await repository.hostile_ips(min_score=1, since=now - timedelta(days=1))
    assert hostile[0] == "198.51.100.7"


async def test_la_purge_rgpd(repository, pg_engine):
    """S4-04 : partition expirée supprimée d'un bloc, reste supprimé ligne à ligne, journal."""
    await repository.maintain(today=date(2025, 1, 15))
    await capture(repository, occurred_at=datetime(2025, 1, 10, tzinfo=UTC))
    await capture(repository, source_ip="203.0.113.99", occurred_at=datetime.now(UTC))

    summary = await repository.purge(datetime(2025, 6, 1, tzinfo=UTC))
    assert summary["event_2025_01"] == 1
    [exists] = await fetch_one(pg_engine, "SELECT to_regclass('event_2025_01') IS NOT NULL")
    assert not exists
    assert [str(e.source_ip) for e in await repository.query()] == ["203.0.113.99"]
    assert summary["ip_intel"] == 1, "l'adresse disparue avec ses événements"
    [jobs] = await fetch_one(pg_engine, "SELECT count(*) FROM retention_job")
    assert jobs >= 2


async def test_archivage_des_mois_anciens(repository, pg_engine, tmp_path):
    """Le mois archivé est lisible seul, vérifié, puis sa partition est supprimée."""
    await repository.maintain(today=date(2025, 1, 15))
    for day in (3, 17):
        await capture(repository, occurred_at=datetime(2025, 1, day, tzinfo=UTC))
    await capture(repository, occurred_at=datetime.now(UTC))

    archived = await repository.archive_partitions(date(2025, 2, 1), tmp_path)
    assert [(a["partition"], a["rows"]) for a in archived] == [("event_2025_01", 2)]

    with gzip.open(tmp_path / "event_2025_01.csv.gz", "rt", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2 and {row["service"] for row in rows} == {"ssh"}
    manifest = json.loads((tmp_path / "event_2025_01.json").read_text("utf-8"))
    digest = hashlib.sha256((tmp_path / "event_2025_01.csv.gz").read_bytes()).hexdigest()
    assert manifest["sha256"] == digest and manifest["rows"] == 2
    assert not list(tmp_path.glob("*.tmp"))

    [exists] = await fetch_one(pg_engine, "SELECT to_regclass('event_2025_01') IS NOT NULL")
    assert not exists
    assert len(await repository.query()) == 1, "le mois courant n'est pas touché"
    [logged] = await fetch_one(
        pg_engine, "SELECT count(*) FROM retention_job WHERE partition = 'archive:event_2025_01'"
    )
    assert logged == 1


async def test_allegement_et_mesure_du_stockage(repository):
    old, _ = await capture(
        repository,
        occurred_at=datetime.now(UTC) - timedelta(days=40),
        payload=b"GET /.env HTTP/1.1",
    )
    recent, _ = await capture(repository, payload=b"GET / HTTP/1.1")
    assert await repository.lighten_payloads(datetime.now(UTC) - timedelta(days=30)) == 1
    stored = {e.event_id: e for e in await repository.query()}
    assert stored[old.event_id].payload == b""
    assert stored[old.event_id].payload_sha256 == old.payload_sha256
    assert stored[recent.event_id].payload == b"GET / HTTP/1.1"

    tables = {row["table"] for row in await repository.storage_usage()}
    assert {"ip_intel", "session", "rule_match"} <= tables


async def test_seuils_et_historique_des_alertes(repository):
    thresholds = [
        {
            "id": "volume",
            "metric": "events",
            "threshold": 200.0,
            "window_seconds": 300,
            "silence_seconds": 3600,
            "enabled": True,
        }
    ]
    assert await repository.load_alert_thresholds() == []
    await repository.save_alert_thresholds(thresholds)
    assert await repository.load_alert_thresholds() == thresholds

    when = datetime.now(UTC)
    await repository.record_alert(
        {
            "threshold_id": "volume",
            "triggered_at": when,
            "value": 250.0,
            "threshold": 200.0,
            "status": "sent",
            "channels": {"discord": "sent"},
        }
    )
    [alert] = await repository.recent_alerts()
    assert alert["threshold_id"] == "volume" and alert["value"] == 250.0
    assert alert["channels"] == {"discord": "sent"}


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


async def test_la_session_garde_sa_derniere_activite(repository, pg_engine):
    session_id = uuid4()
    now = datetime.now(UTC)
    await capture(repository, session_id=session_id, occurred_at=now - timedelta(minutes=3))
    await capture(repository, session_id=session_id, occurred_at=now - timedelta(minutes=1))

    started, ended, closed = await fetch_one(
        pg_engine, "SELECT started_at, ended_at, closed FROM session WHERE id = :id", id=session_id
    )
    assert (ended - started, closed) == (timedelta(minutes=2), False)


async def test_seules_les_sessions_inactives_sont_fermees(repository, pg_engine):
    now = datetime.now(UTC)
    idle, active, legacy = uuid4(), uuid4(), uuid4()
    await capture(repository, session_id=idle, occurred_at=now - timedelta(minutes=10))
    await capture(repository, session_id=active, occurred_at=now - timedelta(minutes=1))
    await capture(repository, session_id=legacy, occurred_at=now - timedelta(minutes=20))
    async with pg_engine.begin() as conn:  # session écrite avant #58 : ended_at absent
        await conn.execute(
            text("UPDATE session SET ended_at = NULL WHERE id = :id"), {"id": legacy}
        )

    assert await repository.close_idle_sessions(now - timedelta(minutes=5)) == 2
    assert [s.session_id for s in await repository.open_sessions()] == [active]

    closed, ended = await fetch_one(
        pg_engine, "SELECT closed, ended_at FROM session WHERE id = :id", id=legacy
    )
    assert closed and ended is not None


async def test_une_session_survit_au_redemarrage_du_collecteur(repository, pg_engine):
    """#58 : un événement reçu après un redémarrage rejoint la session en cours."""
    api.app.state.repository = repository
    headers = {"X-Ingest-Token": api.INGEST_TOKEN}
    body = dict(service="ssh", source_ip="203.0.113.77", source_port=40000, dest_port=22)
    tracker = api.tracker
    try:
        async with AsyncClient(
            transport=ASGITransport(app=api.app), base_url="http://test"
        ) as client:
            api.tracker = SessionTracker()
            first = (await client.post("/api/v1/ingest", json=body, headers=headers)).json()
            await client.post("/api/v1/ingest", json=body, headers=headers)

            api.tracker = SessionTracker()  # redémarrage : la mémoire est perdue
            await api.resume_sessions(repository, api.tracker)
            third = (await client.post("/api/v1/ingest", json=body, headers=headers)).json()
    finally:
        api.tracker = tracker
        del api.app.state.repository

    assert third["session_id"] == first["session_id"]
    count, closed = await fetch_one(
        pg_engine, "SELECT event_count, closed FROM session WHERE id = :id", id=first["session_id"]
    )
    assert (count, closed) == (3, False)


async def test_chaine_complete_ingestion_vers_verdict(repository):
    api.app.state.repository = repository
    headers = {"X-Ingest-Token": api.INGEST_TOKEN}
    token, _ = create_access_token("admin")
    try:
        async with AsyncClient(
            transport=ASGITransport(app=api.app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
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
