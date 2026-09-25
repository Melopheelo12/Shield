"""Le regroupement en sessions est une fenêtre d'inactivité, pas une durée fixe."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from shield.collector.ingest.session_tracker import SessionTracker
from shield.common.schema import RawEvent, ServiceName

T0 = datetime(2026, 9, 25, 10, 0, 0, tzinfo=UTC)


def event(offset_seconds: float = 0, ip="192.0.2.10", service=ServiceName.SSH) -> RawEvent:
    return RawEvent(
        occurred_at=T0 + timedelta(seconds=offset_seconds),
        service=service,
        source_ip=IPv4Address(ip),
        source_port=1234,
        dest_port=22,
    )


def test_deux_evenements_rapproches_partagent_la_session():
    tracker = SessionTracker(window_seconds=300)
    assert tracker.attach(event(0)) == tracker.attach(event(120))


def test_au_dela_de_la_fenetre_une_nouvelle_session_demarre():
    tracker = SessionTracker(window_seconds=300)
    assert tracker.attach(event(0)) != tracker.attach(event(400))


def test_la_fenetre_glisse_sur_la_derniere_activite():
    """Une attaque continue reste UNE session, même au-delà de 5 minutes au total."""
    tracker = SessionTracker(window_seconds=300)
    first = tracker.attach(event(0))
    for offset in range(60, 1800, 60):
        assert tracker.attach(event(offset)) == first


def test_deux_services_distincts_donnent_deux_sessions():
    tracker = SessionTracker(window_seconds=300)
    a = tracker.attach(event(0, service=ServiceName.SSH))
    b = tracker.attach(event(1, service=ServiceName.FTP))
    assert a != b


def test_deux_adresses_distinctes_donnent_deux_sessions():
    tracker = SessionTracker(window_seconds=300)
    a = tracker.attach(event(0, ip="192.0.2.10"))
    b = tracker.attach(event(1, ip="192.0.2.11"))
    assert a != b


def test_les_sessions_inactives_sont_fermees():
    tracker = SessionTracker(window_seconds=300)
    tracker.attach(event(0))
    assert tracker.open_count == 1
    closed = tracker.close_expired(T0 + timedelta(seconds=1000))
    assert len(closed) == 1
    assert tracker.open_count == 0
