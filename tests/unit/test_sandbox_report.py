"""Rapport de fin de partie (S4-09) : détecté = au moins une règle, le manqué par technique."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from shield.collector.repositories import InMemoryEventRepository
from shield.collector.sandbox import sandbox_report
from shield.common.schema import NormalizedEvent, ServiceName, Verdict

START = datetime(2026, 10, 12, 14, 0, tzinfo=UTC)


async def store(repo, score, technique="T1110.001", at=START):
    event = NormalizedEvent(
        service=ServiceName.SSH,
        source_ip=ip_address("172.30.0.5"),
        source_port=1,
        dest_port=22,
        occurred_at=at,
        threat_score=score,
        technique_id=technique,
    )
    verdict = Verdict(
        event_id=event.event_id, session_id=None, threat_score=score, profile="indetermine"
    )
    await repo.save(event, verdict)


async def test_taux_de_detection_et_manques():
    repo = InMemoryEventRepository()
    await store(repo, 0, at=START - timedelta(hours=1))  # partie précédente : ignoré
    for _ in range(8):
        await store(repo, 35)
    await store(repo, 0, technique="T1046")
    await store(repo, 0, technique=None)

    report = await sandbox_report(repo, START)
    assert (report["events"], report["detected"], report["detection_rate"]) == (10, 8, 80)
    assert report["target_met"]
    assert report["missed_by_technique"] == [
        {"technique": "Network Service Discovery", "events": 1},
        {"technique": "non classé", "events": 1},
    ]


async def test_partie_vide():
    report = await sandbox_report(InMemoryEventRepository(), START)
    assert report["events"] == 0
    assert report["detection_rate"] is None
    assert not report["target_met"]
