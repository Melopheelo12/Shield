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

# Mêmes familles de motifs que rules/detection_rules.yaml (R-009, R-010, R-011,
# R-015, R-016, R-017) : un événement classé « exploitation » ici doit aussi être
# reconnu par l'agent défenseur, et inversement.
_COMMAND_MARKERS = (
    b";wget",
    b";curl",
    b"wget+http",
    b"wget%20http",
    b"curl+http",
    b"|sh",
    b"| sh",
    b"chmod +x",
    b"busybox",
    b"/bin/sh",
    b"/bin/bash",
    b"$((",
)
#: Vulnérabilités connues (CVE) : exploitation, même quand la forme est une traversée.
_KNOWN_EXPLOIT_MARKERS = (
    b"${jndi:",
    b"() { :;};",
    b"/.%2e/",
    b"eval-stdin.php",
    b"fgt_lang",
    b"/mgmt/tm/util/bash",
    b"/vpn/../vpns/",
    b"/cgi-bin/luci/;stok=",
    b"connector.minimal.php",
)
_DISCOVERY_MARKERS = (
    b"../",
    b"..%2f",
    b"%2e%2e",
    b"..%5c",
    b"/.env",
    b"/.git/",
    b"wp-config",
    b"id_rsa",
    b"/.aws/",
    b"/.ssh/",
)
_EXPLOIT_MARKERS = (
    b"union select",
    b"union%20select",
    b"union+select",
    b"' or '1'='1",
    b"%27%20or%20",
    b"%27+or+",
    b"information_schema",
    b"<script",
    b"%3cscript",
    b"onerror=",
)


class MitreMapper:
    """Règles de correspondance, appliquées dans l'ordre du plus spécifique au plus général."""

    def map(self, event: RawEvent | NormalizedEvent) -> str | None:
        payload = event.payload.lower()

        if any(marker in payload for marker in _COMMAND_MARKERS):
            return "T1059"
        if any(marker in payload for marker in _KNOWN_EXPLOIT_MARKERS):
            return "T1190"
        if any(marker in payload for marker in _DISCOVERY_MARKERS):
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
