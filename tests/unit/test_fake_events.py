"""Le générateur doit être reproductible : c'est ce qui permet de rejouer un scénario."""

import random
from datetime import UTC, datetime
from ipaddress import IPv4Address

from shield.common.schema import RawEvent
from shield.tools.fake_events import make_burst, make_event


def test_meme_graine_meme_sequence():
    a = [make_event(random.Random(42)) for _ in range(5)]
    b = [make_event(random.Random(42)) for _ in range(5)]
    assert [e.service for e in a] == [e.service for e in b]
    assert [e.username for e in a] == [e.username for e in b]


def test_les_evenements_produits_sont_valides():
    rng = random.Random(7)
    for _ in range(200):
        event = make_event(rng)
        assert isinstance(event, RawEvent)
        RawEvent.model_validate(event.model_dump(mode="json"))


def test_les_adresses_restent_dans_les_plages_documentaires():
    """Aucune vraie adresse dans un jeu de test (RFC 5737)."""
    rng = random.Random(3)
    for _ in range(200):
        ip = str(make_event(rng).source_ip)
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_une_rafale_vient_bien_dune_seule_adresse():
    events = make_burst(
        random.Random(1),
        count=30,
        source_ip=IPv4Address("203.0.113.7"),
        start=datetime(2026, 9, 25, tzinfo=UTC),
    )
    assert len({str(e.source_ip) for e in events}) == 1
    assert len(events) == 30
