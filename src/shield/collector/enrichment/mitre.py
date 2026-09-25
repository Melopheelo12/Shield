"""Correspondance événement → technique MITRE ATT&CK (US-09).

La table est volontairement petite et explicite : elle est testée unitairement et
lisible en revue. Une correspondance introuvable renvoie ``None``, jamais une
technique approximative — mieux vaut « non classé » qu'une étiquette fausse.
"""

from __future__ import annotations

from shield.common.schema import NormalizedEvent, RawEvent

#: Identifiant -> libellé, pour l'affichage et la documentation.
TECHNIQUES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1046": "Network Service Discovery",
    "T1190": "Exploit Public-Facing Application",
    "T1083": "File and Directory Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
}

_EXPLOIT_MARKERS = (b"../", b"..%2f", b"union select", b"' or '1'='1", b"<script")
_COMMAND_MARKERS = (b";wget ", b";curl ", b"/bin/sh", b"$((")


class MitreMapper:
    """Règles de correspondance, appliquées dans l'ordre du plus spécifique au plus général."""

    def map(self, event: RawEvent | NormalizedEvent) -> str | None:
        payload = event.payload.lower()

        if any(marker in payload for marker in _COMMAND_MARKERS):
            return "T1059"
        if b"../" in payload or b"..%2f" in payload:
            return "T1083"
        if any(marker in payload for marker in _EXPLOIT_MARKERS):
            return "T1190"
        if event.username and event.password:
            return "T1110.001"
        if event.username and not event.password:
            return "T1110.003"
        if not event.username and not event.password:
            return "T1046"
        return None

    @staticmethod
    def label(technique_id: str | None) -> str:
        if technique_id is None:
            return "non classé"
        return TECHNIQUES.get(technique_id, technique_id)
