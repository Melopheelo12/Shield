"""Contrat d'événement partagé entre les leurres, le collecteur et le tableau de bord.

C'est le SEUL point de couplage entre la lane back-end (Ryan) et la lane front-end
(Antho). Toute modification ici doit être accompagnée d'une régénération des types
TypeScript (``make types``) — la CI échoue si les deux divergent.

Les huit champs obligatoires de ``RawEvent`` sont contractuels : ils correspondent
à la user story US-01 et ne peuvent pas être retirés sans changer la version de l'API.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_serializer, field_validator

#: Taille maximale de charge utile conservée (US-06).
MAX_PAYLOAD_BYTES = 4096


class ServiceName(StrEnum):
    """Les trois leurres du MVP. Liste fermée : un service inconnu est un rejet."""

    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"


class EnrichmentStatus(StrEnum):
    """Suit la dégradation gracieuse de l'enrichissement (US-10)."""

    PENDING = "pending"
    DONE = "done"
    PARTIAL = "partial"


class AttackerProfile(StrEnum):
    """Profils produits par l'agent défenseur (US-14). Liste fermée et documentée."""

    OPPORTUNISTIC_SCAN = "balayage_opportuniste"
    TARGETED_BRUTEFORCE = "force_brute_ciblee"
    EXPLOITATION_ATTEMPT = "tentative_exploitation"
    UNDETERMINED = "indetermine"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RawEvent(BaseModel):
    """Événement tel qu'émis par un leurre.

    L'entrée est fournie par un attaquant : la validation est stricte par construction,
    et une charge utile trop grande est tronquée plutôt que rejetée (on ne perd jamais
    un événement à cause de sa taille).
    """

    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=_utcnow)
    service: ServiceName
    source_ip: IPv4Address | IPv6Address
    source_port: Annotated[int, Field(ge=0, le=65535)]
    dest_port: Annotated[int, Field(ge=0, le=65535)]
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=255)

    payload: bytes = b""
    payload_truncated: bool = False
    #: Empreinte de la charge utile **complète**, calculée avant la troncature à 4 Ko
    #: (US-06). Deux exploits identiques gardent la même empreinte même quand on n'en
    #: conserve que le début. ``None`` pour une charge vide.
    payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("payload", mode="before")
    @classmethod
    def _decode_payload(cls, value: object) -> bytes:
        """Accepte des octets bruts ou une chaîne base64 (transport JSON)."""
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except Exception:  # noqa: BLE001 - une charge illisible reste une donnée
                return value.encode("utf-8", errors="replace")
        raise TypeError("payload must be bytes or a base64 string")

    @field_validator("username", "password", mode="before")
    @classmethod
    def _coerce_text(cls, value: object) -> str:
        """Un attaquant envoie parfois des octets non décodables : on ne casse jamais."""
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")[:255]
        return str(value)[:255]

    @field_serializer("payload")
    def _serialize_payload(self, value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    def truncated(self) -> RawEvent:
        """Renvoie une copie dont la charge utile respecte le plafond contractuel.

        Si l'émetteur n'a pas fourni l'empreinte, elle est calculée ici, **avant** de
        tronquer — sauf si la charge est déjà marquée tronquée : l'empreinte d'un
        extrait se ferait passer pour celle de la charge complète.
        """
        update: dict[str, object] = {}
        if self.payload and self.payload_sha256 is None and not self.payload_truncated:
            update["payload_sha256"] = hashlib.sha256(self.payload).hexdigest()
        if len(self.payload) > MAX_PAYLOAD_BYTES:
            update.update(payload=self.payload[:MAX_PAYLOAD_BYTES], payload_truncated=True)
        return self.model_copy(update=update) if update else self


class NormalizedEvent(RawEvent):
    """``RawEvent`` augmenté de la session, de l'enrichissement et du verdict."""

    session_id: UUID | None = None

    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    asn: int | None = None
    as_org: str | None = None
    reputation_score: Annotated[int, Field(ge=0, le=100)] | None = None
    technique_id: str | None = None
    enrichment_status: EnrichmentStatus = EnrichmentStatus.PENDING

    threat_score: Annotated[int, Field(ge=0, le=100)] = 0


class RuleMatch(BaseModel):
    """Une règle déclenchée, avec sa contribution au score (US-13)."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    weight: int
    contribution: int


class Verdict(BaseModel):
    """Sortie de l'agent défenseur pour un événement.

    ``sum(m.contribution for m in matches) == threat_score`` est un invariant :
    c'est ce qui rend le score explicable et vérifiable.
    """

    event_id: UUID
    session_id: UUID | None
    threat_score: Annotated[int, Field(ge=0, le=100)]
    profile: AttackerProfile
    matches: list[RuleMatch] = Field(default_factory=list)

    def is_consistent(self) -> bool:
        return sum(m.contribution for m in self.matches) == self.threat_score
