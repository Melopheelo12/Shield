"""Rechargement à chaud (S2-06) : une règle valide s'applique, une règle cassée jamais."""

import os
from pathlib import Path

import pytest

from shield.collector.defender import DefenderAgent, RuleEngine, RuleReloader
from shield.collector.defender.engine import RuleError

RULE = """
- id: R-900
  name: test-rule
  description: Règle de test.
  severity: low
  weight: {weight}
  condition:
    field: service
    op: {op}
    value: ssh
"""


def write(path: Path, text: str, bump: int) -> None:
    """Écrit puis force une date de modification distincte (systèmes de fichiers grossiers)."""
    path.write_text(text, encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + bump * 1_000_000_000))


@pytest.fixture
def rules_file(tmp_path):
    path = tmp_path / "rules.yaml"
    write(path, RULE.format(weight=10, op="eq"), 0)
    return path


async def test_une_modification_valide_est_appliquee(rules_file):
    agent = DefenderAgent(engine=RuleEngine.from_file(rules_file))
    synced = []

    async def on_reload(rules):
        synced.append([rule.weight for rule in rules])

    reloader = RuleReloader(agent, rules_file, on_reload=on_reload)
    assert not await reloader.reload_if_changed(), "fichier inchangé : rien à faire"

    write(rules_file, RULE.format(weight=42, op="eq"), 1)
    assert await reloader.reload_if_changed()
    assert agent.engine.rules[0].weight == 42
    assert synced == [[42]]


@pytest.mark.parametrize(
    "broken",
    [
        RULE.format(weight=10, op="nope"),
        RULE.format(weight=0, op="eq"),
        RULE.format(weight=10, op="eq") + RULE.format(weight=5, op="eq"),  # id en double
        "- id: [pas: du yaml",
        "pas une liste",
    ],
)
async def test_un_fichier_casse_n_est_jamais_applique(rules_file, broken):
    agent = DefenderAgent(engine=RuleEngine.from_file(rules_file))
    before = agent.engine
    reloader = RuleReloader(agent, rules_file)

    write(rules_file, broken, 1)
    assert not await reloader.reload_if_changed()
    assert agent.engine is before
    assert reloader.last_error

    write(rules_file, RULE.format(weight=30, op="eq"), 2)
    assert await reloader.reload_if_changed()
    assert reloader.last_error is None


async def test_un_echec_de_synchronisation_sera_retente(rules_file):
    agent = DefenderAgent(engine=RuleEngine.from_file(rules_file))
    calls = []

    async def flaky(rules):
        calls.append(None)
        if len(calls) == 1:
            raise ConnectionError("base indisponible")

    reloader = RuleReloader(agent, rules_file, on_reload=flaky)
    write(rules_file, RULE.format(weight=50, op="eq"), 1)
    with pytest.raises(ConnectionError):
        await reloader.reload_if_changed()
    assert agent.engine.rules[0].weight == 10, "pas de bascule sans synchronisation"

    assert await reloader.reload_if_changed()
    assert agent.engine.rules[0].weight == 50


@pytest.mark.parametrize(
    "condition",
    [
        "{all: []}",
        "{any: pas-une-liste}",
        "{field: service}",
        "{op: eq, value: ssh}",
        "{field: username, op: in, value: root}",
        "{not: 3}",
    ],
)
def test_une_condition_invalide_est_refusee_au_chargement(tmp_path, condition):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "- id: R-901\n  name: x\n  description: x\n  severity: low\n  weight: 5\n"
        f"  condition: {condition}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError):
        RuleEngine.from_file(path)


def test_le_fichier_livre_passe_la_validation():
    assert RuleEngine.from_file("rules/detection_rules.yaml").rules
