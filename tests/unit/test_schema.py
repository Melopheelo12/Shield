"""Le contrat d'événement doit survivre à tout ce qu'un attaquant peut envoyer."""

import hashlib
from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from shield.common.schema import (
    MAX_PAYLOAD_BYTES,
    NormalizedEvent,
    RawEvent,
    ServiceName,
    Verdict,
)
from shield.tools.gen_ts_types import render


def make(**overrides):
    base = dict(
        service=ServiceName.SSH,
        source_ip=IPv4Address("192.0.2.10"),
        source_port=44444,
        dest_port=22,
    )
    base.update(overrides)
    return RawEvent(**base)


def test_les_huit_champs_obligatoires_sont_presents():
    event = make(username="root", password="123456")
    dumped = event.model_dump()
    for field in (
        "event_id",
        "occurred_at",
        "service",
        "source_ip",
        "source_port",
        "dest_port",
        "username",
        "password",
    ):
        assert field in dumped


def test_service_inconnu_est_rejete():
    with pytest.raises(ValidationError):
        make(service="telnet")


def test_port_hors_bornes_est_rejete():
    with pytest.raises(ValidationError):
        make(source_port=70000)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00\x01\x02\xff\xfe",  # binaire pur
        "café".encode("utf-16"),  # UTF-8 invalide
        b"' OR '1'='1",  # injection SQL
        b"<script>alert(1)</script>",  # XSS
        b"../../../../etc/passwd",  # traversee de repertoire
        b"\xc3\x28",  # sequence UTF-8 malformee
    ],
)
def test_charges_malveillantes_sont_stockees_inertes(payload):
    """Attendu : tout est accepté, rien n'est interprété, rien ne lève."""
    event = make(payload=payload)
    assert event.payload == payload


def test_identifiants_non_decodables_ne_cassent_pas():
    event = make(username=b"\xff\xfe", password=b"\x00")
    assert isinstance(event.username, str)
    assert isinstance(event.password, str)


def test_charge_utile_enorme_est_tronquee_pas_rejetee():
    event = make(payload=b"A" * (MAX_PAYLOAD_BYTES * 3)).truncated()
    assert len(event.payload) == MAX_PAYLOAD_BYTES
    assert event.payload_truncated is True


def test_charge_utile_courte_reste_intacte():
    event = make(payload=b"hello").truncated()
    assert event.payload == b"hello"
    assert event.payload_truncated is False


def test_identifiants_tres_longs_sont_bornes():
    event = make(username="a" * 5000, password="b" * 5000)
    assert len(event.username) == 255
    assert len(event.password) == 255


def test_serialisation_json_puis_relecture_est_stable():
    original = make(username="admin", password="admin", payload=b"\x00binaire\xff")
    restored = RawEvent.model_validate(original.model_dump(mode="json"))
    assert restored.payload == original.payload
    assert restored.source_ip == original.source_ip


def test_verdict_incoherent_est_detectable():
    verdict = Verdict(
        event_id=make().event_id, session_id=None, threat_score=50, profile="indetermine"
    )
    assert verdict.is_consistent() is False  # aucune règle mais un score : incohérent


def test_horodatage_par_defaut_est_en_utc():
    event = make()
    assert event.occurred_at.tzinfo is not None
    assert event.occurred_at <= datetime.now(UTC)


def test_l_empreinte_porte_sur_la_charge_complete_pas_sur_l_extrait():
    """US-06 : deux exploits identiques gardent la même empreinte, même tronqués."""
    full = b"A" * (MAX_PAYLOAD_BYTES * 3)
    event = make(payload=full).truncated()
    assert event.payload_truncated
    assert event.payload_sha256 == hashlib.sha256(full).hexdigest()


def test_l_empreinte_fournie_par_le_leurre_est_conservee():
    digest = hashlib.sha256(b"charge vue par le leurre").hexdigest()
    event = make(payload=b"extrait", payload_truncated=True, payload_sha256=digest).truncated()
    assert event.payload_sha256 == digest


def test_un_extrait_deja_tronque_ne_recoit_pas_d_empreinte_trompeuse():
    assert make(payload=b"extrait", payload_truncated=True).truncated().payload_sha256 is None


def test_sans_charge_pas_d_empreinte():
    assert make().truncated().payload_sha256 is None


@pytest.mark.parametrize("digest", ["abc", "G" * 64, "A" * 64])
def test_une_empreinte_mal_formee_est_refusee(digest):
    with pytest.raises(ValidationError):
        make(payload=b"x", payload_sha256=digest)


@pytest.mark.parametrize("model", [RawEvent, NormalizedEvent])
def test_chaque_champ_du_contrat_existe_cote_typescript(model):
    """Le gabarit TypeScript est écrit à la main : un champ ajouté ici doit l'être là."""
    rendered = render()
    for field in model.model_fields:
        assert f"  {field}:" in rendered, f"{model.__name__}.{field} absent de events.ts"
