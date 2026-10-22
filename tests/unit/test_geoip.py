"""GeoLite2 hors ligne (S2-01) : pays et ASN, sans jamais lever ni bloquer l'ingestion."""

from ipaddress import ip_address
from types import SimpleNamespace

import pytest

from shield.collector.enrichment.geoip import EMPTY, MAX_AS_ORG_CHARS, GeoInfo, GeoIpEnricher

PUBLIC = ip_address("8.8.8.8")


class AddressNotFoundError(Exception):
    """Même nom que ``geoip2.errors.AddressNotFoundError`` : le cas courant, pas une erreur."""


class FakeReader:
    """Tient lieu de ``geoip2.database.Reader`` : aucune base .mmdb requise en CI."""

    def __init__(self, city=None, asn=None, error: Exception | None = None):
        self._city = city or {}
        self._asn = asn or {}
        self._error = error
        self.calls = 0
        self.closed = False

    def _get(self, table, address):
        self.calls += 1
        if self._error is not None:
            raise self._error
        if address not in table:
            raise AddressNotFoundError(address)
        return table[address]

    def city(self, address):
        return self._get(self._city, address)

    def asn(self, address):
        return self._get(self._asn, address)

    def close(self):
        self.closed = True


def city_record(iso_code):
    return SimpleNamespace(country=SimpleNamespace(iso_code=iso_code))


def asn_record(number, org):
    return SimpleNamespace(autonomous_system_number=number, autonomous_system_organization=org)


@pytest.fixture
def enricher():
    return GeoIpEnricher(
        city=FakeReader(city={"8.8.8.8": city_record("US"), "2001:4860::1": city_record("US")}),
        asn=FakeReader(asn={"8.8.8.8": asn_record(15169, "GOOGLE")}),
    )


def test_pays_et_asn_d_une_adresse_publique(enricher):
    assert enricher.lookup(PUBLIC) == GeoInfo(country_code="US", asn=15169, as_org="GOOGLE")


def test_ipv6(enricher):
    assert enricher.lookup(ip_address("2001:4860::1")).country_code == "US"


@pytest.mark.parametrize(
    "address", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "192.0.2.10", "::1", "fe80::1"]
)
def test_une_adresse_non_routable_n_est_pas_recherchee(enricher, address):
    """Sandbox, réseau Docker, plages de documentation : rien à géolocaliser."""
    assert enricher.lookup(ip_address(address)) == EMPTY
    assert enricher._city.calls == enricher._asn.calls == 0


def test_une_adresse_absente_des_bases_donne_un_resultat_vide(enricher):
    assert enricher.lookup(ip_address("1.1.1.1")) == EMPTY


def test_les_deux_bases_se_degradent_independamment():
    sans_asn = GeoIpEnricher(city=FakeReader(city={"8.8.8.8": city_record("US")}))
    assert sans_asn.lookup(PUBLIC) == GeoInfo(country_code="US")

    sans_pays = GeoIpEnricher(asn=FakeReader(asn={"8.8.8.8": asn_record(15169, "GOOGLE")}))
    assert sans_pays.lookup(PUBLIC) == GeoInfo(asn=15169, as_org="GOOGLE")


@pytest.mark.parametrize("error", [ValueError("base corrompue"), OSError("disque"), RuntimeError()])
def test_une_base_defaillante_ne_leve_jamais(error):
    broken = GeoIpEnricher(city=FakeReader(error=error), asn=FakeReader(error=error))
    assert broken.lookup(PUBLIC) == EMPTY


@pytest.mark.parametrize("iso_code", [None, "", "USA", "u", "1A", "ÉÉ"])
def test_un_code_pays_hors_contrat_est_ecarte(iso_code):
    enricher = GeoIpEnricher(city=FakeReader(city={"8.8.8.8": city_record(iso_code)}))
    assert enricher.lookup(PUBLIC).country_code is None


def test_le_code_pays_est_normalise_en_majuscules():
    enricher = GeoIpEnricher(city=FakeReader(city={"8.8.8.8": city_record("fr")}))
    assert enricher.lookup(PUBLIC).country_code == "FR"


@pytest.mark.parametrize(
    "number,org,expected",
    [
        (None, None, GeoInfo()),
        (-1, "   ", GeoInfo()),
        (True, "X", GeoInfo(as_org="X")),
        (64500, "  Opérateur  ", GeoInfo(asn=64500, as_org="Opérateur")),
        (64500, "A" * 500, GeoInfo(asn=64500, as_org="A" * MAX_AS_ORG_CHARS)),
    ],
)
def test_l_asn_respecte_le_schema_ip_intel(number, org, expected):
    enricher = GeoIpEnricher(asn=FakeReader(asn={"8.8.8.8": asn_record(number, org)}))
    assert enricher.lookup(PUBLIC) == expected


def test_bases_absentes_au_demarrage(tmp_path, caplog):
    enricher = GeoIpEnricher.from_paths(tmp_path / "absente.mmdb", None)
    assert not enricher.available
    assert enricher.lookup(PUBLIC) == EMPTY
    assert "absente" in caplog.text


def test_base_illisible_au_demarrage(tmp_path):
    garbage = tmp_path / "GeoLite2-City.mmdb"
    garbage.write_bytes(b"ceci n'est pas une base maxmind")
    enricher = GeoIpEnricher.from_paths(garbage, garbage)
    assert not enricher.available
    assert enricher.lookup(PUBLIC) == EMPTY


def test_la_fermeture_libere_les_bases(enricher):
    city, asn = enricher._city, enricher._asn
    enricher.close()
    assert city.closed and asn.closed
    assert enricher.lookup(PUBLIC) == EMPTY
    enricher.close()  # idempotente


def test_as_update_couvre_les_champs_du_contrat():
    from shield.common.schema import NormalizedEvent

    info = GeoInfo(country_code="FR", asn=3215, as_org="Orange")
    assert set(info.as_update()) <= set(NormalizedEvent.model_fields)
