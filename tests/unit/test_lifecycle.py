"""Cycle de vie des données : allègement, archivage, et purge RGPD qui couvre les archives."""

from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address

import pytest

from shield.collector.lifecycle import (
    LifecycleSettings,
    archive_month_end,
    first_day_months_ago,
    purge_archives,
    run_lifecycle,
)
from shield.collector.repositories import InMemoryEventRepository
from shield.common.schema import NormalizedEvent, ServiceName, Verdict

NOW = datetime(2026, 10, 12, 4, 0, tzinfo=UTC)


async def store(repo, at, payload=b"GET /.env HTTP/1.1"):
    event = NormalizedEvent(
        service=ServiceName.HTTP,
        source_ip=ip_address("203.0.113.9"),
        source_port=1,
        dest_port=80,
        payload=payload,
        payload_sha256="a" * 64,
        occurred_at=at,
    )
    verdict = Verdict(
        event_id=event.event_id, session_id=None, threat_score=8, profile="indetermine"
    )
    await repo.save(event, verdict)
    return event


@pytest.mark.parametrize(
    "today,months,expected",
    [
        (date(2026, 10, 12), 3, date(2026, 7, 1)),
        (date(2026, 2, 28), 3, date(2025, 11, 1)),
        (date(2026, 1, 1), 12, date(2025, 1, 1)),
        (date(2026, 3, 31), 0, date(2026, 3, 1)),
    ],
)
def test_premier_jour_des_mois_passes(today, months, expected):
    assert first_day_months_ago(today, months) == expected


def test_fin_du_mois_d_une_archive():
    assert archive_month_end("event_2025_12.csv.gz") == date(2026, 1, 1)
    assert archive_month_end("event_2026_03.json") == date(2026, 4, 1)
    assert archive_month_end("notes.txt") is None
    assert archive_month_end("event_2026_03.csv.gz.tmp") is None


def test_la_purge_rgpd_s_applique_aussi_aux_archives(tmp_path):
    for name in (
        "event_2025_09.csv.gz",
        "event_2025_09.json",
        "event_2025_10.csv.gz",
        "event_2025_11.csv.gz",
        "autre-fichier.txt",
    ):
        (tmp_path / name).write_bytes(b"x")
    removed = purge_archives(tmp_path, cutoff=date(2025, 11, 1))
    assert removed == ["event_2025_09.csv.gz", "event_2025_09.json", "event_2025_10.csv.gz"]
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "autre-fichier.txt",
        "event_2025_11.csv.gz",
    ]


def test_dossier_d_archives_absent(tmp_path):
    assert purge_archives(tmp_path / "absent", date(2026, 1, 1)) == []


async def test_allegement_des_charges_utiles_anciennes():
    repo = InMemoryEventRepository()
    old = await store(repo, NOW - timedelta(days=45))
    recent = await store(repo, NOW - timedelta(days=2))
    report = await run_lifecycle(
        repo, LifecycleSettings(payload_retention_days=30, archive_after_months=0), now=NOW
    )
    assert report["payloads_lightened"] == 1
    by_id = {e.event_id: e for e in repo.events}
    assert by_id[old.event_id].payload == b""
    assert by_id[old.event_id].payload_sha256 == "a" * 64, "l'empreinte reste"
    assert by_id[recent.event_id].payload == recent.payload


async def test_chaque_palier_se_desactive(tmp_path):
    repo = InMemoryEventRepository()
    await store(repo, NOW - timedelta(days=500))
    settings = LifecycleSettings(
        payload_retention_days=0, archive_after_months=0, retention_days=0, archive_dir=tmp_path
    )
    assert await run_lifecycle(repo, settings, now=NOW) == {}
    assert len(repo.events) == 1


async def test_archivage_suspendu_sans_dossier_inscriptible(tmp_path):
    repo = InMemoryEventRepository()
    settings = LifecycleSettings(archive_after_months=3, archive_dir=tmp_path / "absent")
    report = await run_lifecycle(repo, settings, now=NOW)
    assert "archived" not in report


async def test_passage_complet(tmp_path):
    repo = InMemoryEventRepository()
    await store(repo, NOW - timedelta(days=400))
    (tmp_path / "event_2025_01.csv.gz").write_bytes(b"x")
    report = await run_lifecycle(repo, LifecycleSettings(archive_dir=tmp_path), now=NOW)
    assert report["purged"] == {"event": 1}
    assert report["archived"] == []
    assert report["archives_purged"] == ["event_2025_01.csv.gz"]
