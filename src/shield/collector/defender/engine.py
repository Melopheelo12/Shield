"""Moteur de règles de l'agent défenseur.

Trois propriétés sont non négociables et testées unitairement :

1. **Déterminisme** (US-15) — mêmes événements, mêmes règles, même version : même
   score et même profil. Aucune source d'aléa, aucune lecture d'horloge en dehors des
   fenêtres explicitement fournies dans le contexte.
2. **Explicabilité** (US-13) — la somme des contributions des règles déclenchées est
   exactement égale au score affiché. ``Verdict.is_consistent()`` le vérifie.
3. **Rapidité** (US-18) — l'évaluation est une suite de comparaisons sur un
   dictionnaire ; les compteurs de fenêtre glissante sont fournis par Redis et ne sont
   jamais recalculés ici.

Le score est une **somme plafonnée à 100**, jamais une moyenne : une seule règle
critique doit pouvoir saturer le score, sinon une attaque grave serait diluée par des
signaux anodins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shield.common.schema import (
    AttackerProfile,
    NormalizedEvent,
    RuleMatch,
    Severity,
    Verdict,
)

MAX_SCORE = 100


class RuleError(ValueError):
    """Règle syntaxiquement invalide. Détectée au chargement, jamais à l'exécution."""


# --------------------------------------------------------------------------- opérateurs


def _op_eq(value: Any, expected: Any) -> bool:
    return value == expected


def _op_ne(value: Any, expected: Any) -> bool:
    return value != expected


def _op_gte(value: Any, expected: Any) -> bool:
    return value is not None and value >= expected


def _op_lte(value: Any, expected: Any) -> bool:
    return value is not None and value <= expected


def _op_in(value: Any, expected: Any) -> bool:
    return value in expected


def _op_contains(value: Any, expected: Any) -> bool:
    if value is None:
        return False
    haystack = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    return str(expected).lower() in haystack.lower()


def _op_is_empty(value: Any, expected: Any) -> bool:
    return (not value) == bool(expected)


OPERATORS = {
    "eq": _op_eq,
    "ne": _op_ne,
    "gte": _op_gte,
    "lte": _op_lte,
    "in": _op_in,
    "contains": _op_contains,
    "is_empty": _op_is_empty,
}


@dataclass(frozen=True)
class Rule:
    """Une règle de détection, telle que décrite dans ``rules/detection_rules.yaml``."""

    id: str
    name: str
    description: str
    severity: Severity
    weight: int
    condition: dict[str, Any]
    window_seconds: int = 0
    profile_hint: AttackerProfile | None = None
    enabled: bool = True
    version: int = 1

    def matches(self, context: dict[str, Any]) -> bool:
        return _evaluate(self.condition, context)


def _evaluate(node: dict[str, Any], context: dict[str, Any]) -> bool:
    """Évalue un nœud de condition : ``all``, ``any``, ``not`` ou une comparaison."""
    if "all" in node:
        return all(_evaluate(child, context) for child in node["all"])
    if "any" in node:
        return any(_evaluate(child, context) for child in node["any"])
    if "not" in node:
        return not _evaluate(node["not"], context)

    field_name = node.get("field")
    operator = node.get("op")
    if field_name is None or operator is None:
        raise RuleError(f"condition incomplète : {node!r}")
    handler = OPERATORS.get(operator)
    if handler is None:
        raise RuleError(f"opérateur inconnu : {operator!r}")
    return handler(context.get(field_name), node.get("value"))


def _validate(node: Any, rule_id: str) -> None:
    """Parcourt l'arbre de condition au chargement, pour ne jamais échouer à l'évaluation."""
    if not isinstance(node, dict):
        raise RuleError(f"règle {rule_id} : nœud de condition illisible {node!r}")
    if "all" in node or "any" in node:
        children = node.get("all", node.get("any"))
        if not isinstance(children, list) or not children:
            raise RuleError(f"règle {rule_id} : all / any attend une liste non vide")
        for child in children:
            _validate(child, rule_id)
        return
    if "not" in node:
        _validate(node["not"], rule_id)
        return
    if not isinstance(node.get("field"), str):
        raise RuleError(f"règle {rule_id} : condition incomplète {node!r}")
    if node.get("op") not in OPERATORS:
        raise RuleError(f"règle {rule_id} : opérateur inconnu {node.get('op')!r}")
    if node["op"] == "in" and not isinstance(node.get("value"), list):
        raise RuleError(f"règle {rule_id} : l'opérateur in attend une liste")


@dataclass
class RuleEngine:
    """Charge les règles et les évalue contre un événement enrichi et son contexte."""

    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> RuleEngine:
        """Charge et **valide** tout le fichier : une seule règle invalide le refuse entier."""
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
        except yaml.YAMLError as exc:
            raise RuleError(f"YAML invalide : {exc}") from exc
        if not isinstance(raw, list):
            raise RuleError("le fichier de règles doit être une liste")
        rules = [cls._parse(item) for item in raw]
        ids = [rule.id for rule in rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise RuleError(f"identifiants en double : {duplicates}")
        return cls(rules=rules)

    @staticmethod
    def _parse(item: Any) -> Rule:
        if not isinstance(item, dict):
            raise RuleError(f"règle illisible : {item!r}")
        required = ("id", "name", "description", "severity", "weight", "condition")
        missing = [key for key in required if key not in item]
        rule_id = item.get("id", "?")
        if missing:
            raise RuleError(f"règle {rule_id} : champs manquants {missing}")
        hint = item.get("profile_hint")
        try:
            rule = Rule(
                id=str(item["id"]),
                name=item["name"],
                description=" ".join(str(item["description"]).split()),
                severity=Severity(item["severity"]),
                weight=int(item["weight"]),
                condition=item["condition"],
                window_seconds=int(item.get("window_seconds", 0)),
                profile_hint=AttackerProfile(hint) if hint else None,
                enabled=bool(item.get("enabled", True)),
                version=int(item.get("version", 1)),
            )
        except (TypeError, ValueError) as exc:
            raise RuleError(f"règle {rule_id} : {exc}") from exc
        if not 0 < rule.weight <= MAX_SCORE:
            raise RuleError(f"règle {rule_id} : poids hors de ]0, {MAX_SCORE}]")
        _validate(rule.condition, rule.id)
        return rule

    def match(self, context: dict[str, Any]) -> list[Rule]:
        """Règles déclenchées, dans l'ordre stable du fichier (déterminisme)."""
        return [rule for rule in self.rules if rule.enabled and rule.matches(context)]


def build_context(event: NormalizedEvent, counters: dict[str, int] | None = None) -> dict[str, Any]:
    """Aplatit un événement et ses compteurs en un dictionnaire évaluable.

    Les compteurs viennent de Redis (``counter.*``) : le moteur ne les calcule jamais
    lui-même, ce qui garantit à la fois la rapidité et la testabilité.
    """
    context: dict[str, Any] = {
        "service": event.service.value,
        "source_ip": str(event.source_ip),
        "dest_port": event.dest_port,
        "username": event.username,
        "password": event.password,
        "payload": event.payload,
        "payload_truncated": event.payload_truncated,
        "country_code": event.country_code,
        "asn": event.asn,
        "reputation_score": event.reputation_score,
        "technique_id": event.technique_id,
    }
    for key, value in (counters or {}).items():
        context[f"counter.{key}"] = value
    return context


class ScoreCalculator:
    """Somme plafonnée des poids, répartie en contributions qui somment au score."""

    @staticmethod
    def compute(rules: list[Rule]) -> tuple[int, list[RuleMatch]]:
        total = sum(rule.weight for rule in rules)
        score = min(total, MAX_SCORE)

        matches: list[RuleMatch] = []
        remaining = score
        for index, rule in enumerate(rules):
            if index == len(rules) - 1:
                contribution = remaining
            else:
                contribution = round(rule.weight * score / total) if total else 0
                contribution = min(contribution, remaining)
            remaining -= contribution
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    weight=rule.weight,
                    contribution=contribution,
                )
            )
        return score, matches


class ThreatProfiler:
    """Classe une session dans un profil de la liste fermée d'``AttackerProfile``."""

    @staticmethod
    def classify(rules: list[Rule]) -> AttackerProfile:
        severity_order = {
            Severity.CRITICAL: 3,
            Severity.HIGH: 2,
            Severity.MEDIUM: 1,
            Severity.LOW: 0,
        }
        hinted = [rule for rule in rules if rule.profile_hint is not None]
        if not hinted:
            return AttackerProfile.UNDETERMINED
        best = max(hinted, key=lambda rule: (severity_order[rule.severity], rule.weight))
        assert best.profile_hint is not None
        return best.profile_hint


@dataclass
class DefenderAgent:
    """Façade : un événement enrichi entre, un verdict explicable sort."""

    engine: RuleEngine
    calculator: ScoreCalculator = field(default_factory=ScoreCalculator)
    profiler: ThreatProfiler = field(default_factory=ThreatProfiler)

    def evaluate(self, event: NormalizedEvent, counters: dict[str, int] | None = None) -> Verdict:
        context = build_context(event, counters)
        matched = self.engine.match(context)
        score, matches = self.calculator.compute(matched)
        return Verdict(
            event_id=event.event_id,
            session_id=event.session_id,
            threat_score=score,
            profile=self.profiler.classify(matched),
            matches=matches,
        )
