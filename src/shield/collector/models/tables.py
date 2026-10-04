"""Modèles SQLAlchemy — mappés sur le schéma de ``deploy/initdb/001_schema.sql``.

Ces classes ne créent aucune table : elles décrivent à SQLAlchemy la structure
déjà en place. Si le SQL et ces modèles divergent, les tests d'intégration
échouent — c'est le garde-fou.

Deux choix à savoir défendre :

* ``Event`` a une **clé primaire composite** ``(id, occurred_at)``. PostgreSQL
  exige que la clé de partition fasse partie de toute contrainte unique sur une
  table partitionnée. Ce n'est pas un choix esthétique, c'est une contrainte du
  moteur.
* ``Event.session_id`` n'a **pas** de clé étrangère vers ``session``. Une
  contrainte référentielle sur une table partitionnée coûte cher à l'insertion,
  et l'événement est écrit avant que la session soit close. L'intégrité est
  assurée par le collecteur, pas par le moteur — arbitrage performance /
  intégrité assumé.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    Numeric,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shield.collector.models.base import Base


class DecoyService(Base):
    """Les trois leurres. Table de référence, 3 lignes."""

    __tablename__ = "decoy_service"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(16), unique=True)
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[int] = mapped_column(Integer)
    banner_version: Mapped[str] = mapped_column(String(128), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    def __repr__(self) -> str:
        return f"<DecoyService {self.name}:{self.port}>"


class AttackTechnique(Base):
    """Référentiel MITRE ATT&CK utilisé (US-09)."""

    __tablename__ = "attack_technique"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # 'T1110.001'
    name: Mapped[str] = mapped_column(String(128))
    tactic: Mapped[str] = mapped_column(String(64))
    url: Mapped[str | None] = mapped_column(Text, nullable=True)


class IpIntel(Base):
    """Cache d'enrichissement, une ligne par adresse.

    Séparée d'``Event`` : une même IP produit des centaines d'événements, et
    dupliquer pays, ASN et réputation à chaque ligne serait un gâchis.
    """

    __tablename__ = "ip_intel"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    country_code: Mapped[str | None] = mapped_column(CHAR(2), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    as_org: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reputation_score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    reputation_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    total_events: Mapped[int] = mapped_column(BigInteger, default=0)

    def __repr__(self) -> str:
        return f"<IpIntel {self.ip} {self.country_code} AS{self.asn}>"


class Session(Base):
    """Événements d'une même IP sur un même service, à moins de 5 min d'écart (US-04)."""

    __tablename__ = "session"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source_ip: Mapped[str] = mapped_column(INET, ForeignKey("ip_intel.ip", ondelete="CASCADE"))
    service_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("decoy_service.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    attacker_profile: Mapped[str] = mapped_column(String(32), default="indetermine")
    closed: Mapped[bool] = mapped_column(Boolean, default=False)
    from_sandbox: Mapped[bool] = mapped_column(Boolean, default=False)

    service: Mapped[DecoyService] = relationship(lazy="selectin")
    intel: Mapped[IpIntel] = relationship(lazy="selectin")
    matches: Mapped[list[RuleMatch]] = relationship(
        back_populates="session", lazy="selectin", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Session {self.id} {self.source_ip} score={self.threat_score}>"


class Event(Base):
    """LA table centrale. Partitionnée par mois sur ``occurred_at``."""

    __tablename__ = "event"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    service_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("decoy_service.id"))

    # Pas de ForeignKey volontairement : voir la docstring du module.
    session_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    source_ip: Mapped[str] = mapped_column(INET)
    source_port: Mapped[int] = mapped_column(Integer)
    dest_port: Mapped[int] = mapped_column(Integer)
    username: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(String(255), default="")

    payload_excerpt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    payload_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    payload_sha256: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)

    technique_id: Mapped[str | None] = mapped_column(
        String(16), ForeignKey("attack_technique.id"), nullable=True
    )
    threat_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    enrichment_status: Mapped[str] = mapped_column(String(16), default="pending")
    from_sandbox: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        CheckConstraint("threat_score BETWEEN 0 AND 100", name="event_threat_score_range"),
        {"postgresql_partition_by": "RANGE (occurred_at)"},
    )

    def __repr__(self) -> str:
        return f"<Event {self.id} {self.source_ip} {self.username!r} score={self.threat_score}>"


class DetectionRule(Base):
    """Une règle de l'agent défenseur. Versionnée : toute modification incrémente."""

    __tablename__ = "detection_rule"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(16), unique=True)  # 'R-007'
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text)  # en français, sans jargon (US-17)
    condition: Mapped[dict] = mapped_column(JSONB)
    weight: Mapped[int] = mapped_column(SmallInteger)
    severity: Mapped[str] = mapped_column(String(16))
    window_seconds: Mapped[int] = mapped_column(Integer, default=0)
    profile_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)


class RuleMatch(Base):
    """Un déclenchement de règle. C'est cette table qui rend le score explicable (US-13)."""

    __tablename__ = "rule_match"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("detection_rule.id"))
    session_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("session.id", ondelete="CASCADE")
    )
    event_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    contributed_score: Mapped[int] = mapped_column(SmallInteger)

    rule: Mapped[DetectionRule] = relationship(lazy="selectin")
    session: Mapped[Session] = relationship(back_populates="matches")


class AlertChannel(Base):
    __tablename__ = "alert_channel"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    type: Mapped[str] = mapped_column(String(16))  # 'discord' | 'email'
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Alert(Base):
    __tablename__ = "alert"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[int | None] = mapped_column(
        SmallInteger, ForeignKey("detection_rule.id"), nullable=True
    )
    channel_id: Mapped[int | None] = mapped_column(
        SmallInteger, ForeignKey("alert_channel.id"), nullable=True
    )
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metric_value: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    threshold: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BlocklistEntry(Base):
    """Liste d'adresses hostiles exploitable par un pare-feu (US-43)."""

    __tablename__ = "blocklist_entry"

    ip: Mapped[str] = mapped_column(
        INET, ForeignKey("ip_intel.ip", ondelete="CASCADE"), primary_key=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    score: Mapped[int] = mapped_column(SmallInteger, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AppUser(Base):
    """Compte administrateur unique en v1."""

    __tablename__ = "app_user"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiToken(Base):
    __tablename__ = "api_token"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("app_user.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    scopes: Mapped[str] = mapped_column(String(128), default="read")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CveWatch(Base):
    """Résultats de l'agent de veille, corrélés aux observations (US-40)."""

    __tablename__ = "cve_watch"

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cvss: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    matched_events: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SandboxRun(Base):
    """Historique des parties d'entraînement et taux de détection (US-37)."""

    __tablename__ = "sandbox_run"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attacker_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    defender_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scenario: Mapped[str] = mapped_column(String(64), default="libre")
    events_count: Mapped[int] = mapped_column(Integer, default=0)
    detected_count: Mapped[int] = mapped_column(Integer, default=0)
    detection_rate: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)


class EventRejected(Base):
    """Événements malformés : tracés, jamais perdus, et le leurre n'est pas bloqué (§ 4.1)."""

    __tablename__ = "event_rejected"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    raw_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class RetentionJob(Base):
    """Journal des purges RGPD (US-46)."""

    __tablename__ = "retention_job"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    cutoff_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    partition: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deleted_rows: Mapped[int] = mapped_column(BigInteger, default=0)
