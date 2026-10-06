-- =============================================================================
-- SHIELD — schéma initial
--
-- Ce fichier est monté dans /docker-entrypoint-initdb.d du conteneur PostgreSQL :
-- il s'exécute automatiquement à la première création de la base.
--
-- Écrit en SQL brut plutôt qu'en migration ORM pour deux raisons :
--   1. le partitionnement déclaratif s'exprime mal à travers un ORM ;
--   2. le schéma est le même en local, en CI et en production — un seul fichier.
--
-- Référence : documentation technique de l'étape 3, § 3.5.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- decoy_service — les trois leurres. Table de référence, 3 lignes.
-- -----------------------------------------------------------------------------
CREATE TABLE decoy_service (
    id              SMALLSERIAL PRIMARY KEY,
    name            VARCHAR(16)  NOT NULL UNIQUE,
    protocol        VARCHAR(16)  NOT NULL,
    port            INTEGER      NOT NULL CHECK (port BETWEEN 1 AND 65535),
    banner_version  VARCHAR(128) NOT NULL DEFAULT '',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE
);

COMMENT ON TABLE decoy_service IS
    'Les services leurres exposés. La bannière est versionnée (US-02).';

INSERT INTO decoy_service (name, protocol, port, banner_version) VALUES
    ('ssh',  'ssh',  22, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'),
    ('http', 'http', 80, 'nginx'),
    ('ftp',  'ftp',  21, '220 (vsFTPd 3.0.5)');

-- -----------------------------------------------------------------------------
-- attack_technique — référentiel MITRE ATT&CK utilisé.
-- -----------------------------------------------------------------------------
CREATE TABLE attack_technique (
    id      VARCHAR(16)  PRIMARY KEY,          -- ex. 'T1110.001'
    name    VARCHAR(128) NOT NULL,
    tactic  VARCHAR(64)  NOT NULL,
    url     TEXT
);

INSERT INTO attack_technique (id, name, tactic, url) VALUES
    ('T1110.001', 'Brute Force: Password Guessing',   'Credential Access', 'https://attack.mitre.org/techniques/T1110/001/'),
    ('T1110.003', 'Brute Force: Password Spraying',   'Credential Access', 'https://attack.mitre.org/techniques/T1110/003/'),
    ('T1046',     'Network Service Discovery',        'Discovery',         'https://attack.mitre.org/techniques/T1046/'),
    ('T1190',     'Exploit Public-Facing Application','Initial Access',    'https://attack.mitre.org/techniques/T1190/'),
    ('T1083',     'File and Directory Discovery',     'Discovery',         'https://attack.mitre.org/techniques/T1083/'),
    ('T1059',     'Command and Scripting Interpreter','Execution',         'https://attack.mitre.org/techniques/T1059/'),
    ('T1078',     'Valid Accounts',                   'Defense Evasion',   'https://attack.mitre.org/techniques/T1078/');

-- -----------------------------------------------------------------------------
-- ip_intel — cache d'enrichissement, UNE ligne par adresse.
--
-- Séparée de `event` volontairement : une même IP produit des centaines
-- d'événements. Dupliquer pays, ASN et réputation à chaque ligne gaspillerait
-- l'espace et rendrait le rafraîchissement de réputation coûteux.
-- -----------------------------------------------------------------------------
CREATE TABLE ip_intel (
    ip                      INET        PRIMARY KEY,
    country_code            CHAR(2),
    asn                     INTEGER,
    as_org                  VARCHAR(128),
    reputation_score        SMALLINT    CHECK (reputation_score BETWEEN 0 AND 100),
    reputation_checked_at   TIMESTAMPTZ,
    is_tor                  BOOLEAN     NOT NULL DEFAULT FALSE,
    first_seen              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_events            BIGINT      NOT NULL DEFAULT 0
);

-- Sert à identifier les entrées de cache à rafraîchir (réputation > 24 h).
CREATE INDEX ip_intel_reputation_checked_at_idx
    ON ip_intel (reputation_checked_at NULLS FIRST);

COMMENT ON COLUMN ip_intel.ip IS
    'Type INET natif : comparaison et requêtes par sous-réseau sans découpage de chaîne.';

-- -----------------------------------------------------------------------------
-- session — regroupement des événements d''une même IP sur un même service,
-- séparés de moins de 5 minutes (US-04).
-- -----------------------------------------------------------------------------
CREATE TABLE session (
    id               UUID        PRIMARY KEY,
    source_ip        INET        NOT NULL REFERENCES ip_intel (ip) ON DELETE CASCADE,
    service_id       SMALLINT    NOT NULL REFERENCES decoy_service (id),
    started_at       TIMESTAMPTZ NOT NULL,
    ended_at         TIMESTAMPTZ,
    event_count      INTEGER     NOT NULL DEFAULT 0,
    threat_score     SMALLINT    NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    attacker_profile VARCHAR(32) NOT NULL DEFAULT 'indetermine',
    closed           BOOLEAN     NOT NULL DEFAULT FALSE,
    from_sandbox     BOOLEAN     NOT NULL DEFAULT FALSE
);

-- Index PARTIEL : seules les sessions closes sont classées par gravité.
-- Un index partiel reste compact et ne pénalise pas les écritures sur
-- les sessions encore ouvertes, qui sont mises à jour en permanence.
CREATE INDEX session_threat_score_idx
    ON session (threat_score DESC) WHERE closed;

CREATE INDEX session_source_ip_idx ON session (source_ip, started_at DESC);

-- -----------------------------------------------------------------------------
-- event — LA table centrale. PARTITIONNÉE PAR MOIS sur occurred_at.
--
-- Pourquoi partitionner : la purge RGPD (12 mois par défaut) devient un
-- DROP TABLE de partition — instantané — au lieu d'un DELETE massif qui
-- verrouille la table et fait gonfler le WAL.
--
-- Contrainte de PostgreSQL : la clé de partition DOIT faire partie de la clé
-- primaire. D'où la clé composite (id, occurred_at).
-- -----------------------------------------------------------------------------
CREATE TABLE event (
    id                 BIGSERIAL,
    occurred_at        TIMESTAMPTZ NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service_id         SMALLINT    NOT NULL REFERENCES decoy_service (id),
    session_id         UUID,
    source_ip          INET        NOT NULL,
    source_port        INTEGER     NOT NULL CHECK (source_port BETWEEN 0 AND 65535),
    dest_port          INTEGER     NOT NULL CHECK (dest_port BETWEEN 0 AND 65535),
    username           VARCHAR(255) NOT NULL DEFAULT '',
    password           VARCHAR(255) NOT NULL DEFAULT '',
    payload_excerpt    BYTEA,
    payload_truncated  BOOLEAN     NOT NULL DEFAULT FALSE,
    payload_sha256     CHAR(64),
    technique_id       VARCHAR(16) REFERENCES attack_technique (id),
    threat_score       SMALLINT    NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    enrichment_status  VARCHAR(16) NOT NULL DEFAULT 'pending',
    from_sandbox       BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

COMMENT ON COLUMN event.password IS
    'Stocké EN CLAIR : ce ne sont pas des mots de passe légitimes mais ceux que des '
    'attaquants testent. Leur valeur analytique est dans leur contenu (US-03). '
    'Exclus de tout export public non pseudonymisé.';

COMMENT ON COLUMN event.payload_excerpt IS
    'Plafonné à 4 Ko. BYTEA car la charge peut être binaire ou malformée. '
    'Stockée inerte, jamais interprétée.';

-- Les index sont déclarés sur la table parente : PostgreSQL les propage
-- automatiquement à chaque partition, présente et future.
CREATE INDEX event_occurred_at_idx      ON event (occurred_at DESC);
CREATE INDEX event_source_ip_idx        ON event (source_ip, occurred_at DESC);
CREATE INDEX event_session_id_idx       ON event (session_id);
CREATE INDEX event_service_id_idx       ON event (service_id, occurred_at DESC);

-- Pas d'index sur username ni password, malgré le « top 10 des identifiants » :
-- très forte cardinalité, alimentée par des attaquants, et ces classements sont
-- calculés sur une période bornée qui se satisfait de l'index temporel.
-- L'index coûterait plus en écriture qu'il ne rapporterait en lecture.

-- Partitions : le mois courant et le suivant. La création des mois à venir est
-- assurée par la fonction ci-dessous, appelée par le collecteur au démarrage
-- puis chaque jour (PostgresEventRepository.maintain).
CREATE TABLE event_default PARTITION OF event DEFAULT;

CREATE OR REPLACE FUNCTION create_event_partition(target DATE)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    start_date DATE := date_trunc('month', target)::DATE;
    end_date   DATE := (date_trunc('month', target) + INTERVAL '1 month')::DATE;
    part_name  TEXT := 'event_' || to_char(start_date, 'YYYY_MM');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
        RETURN part_name || ' (existe deja)';
    END IF;
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF event FOR VALUES FROM (%L) TO (%L)',
        part_name, start_date, end_date
    );
    RETURN part_name || ' (creee)';
END;
$$;

COMMENT ON FUNCTION create_event_partition IS
    'Cree la partition mensuelle de `event` pour le mois contenant `target`. '
    'Idempotente : appelable sans risque par une tache planifiee.';

SELECT create_event_partition(CURRENT_DATE);
SELECT create_event_partition((CURRENT_DATE + INTERVAL '1 month')::DATE);

-- -----------------------------------------------------------------------------
-- detection_rule / rule_match — l''explicabilité du score (US-13).
--
-- rule_match est une TABLE et non un champ JSON dans `session` : répondre à
-- « quelle règle, combien de fois, sur quelle période » est une agrégation,
-- pas une lecture de document.
-- -----------------------------------------------------------------------------
CREATE TABLE detection_rule (
    id              SMALLSERIAL PRIMARY KEY,
    rule_key        VARCHAR(16)  NOT NULL UNIQUE,     -- 'R-007'
    name            VARCHAR(64)  NOT NULL UNIQUE,
    description     TEXT         NOT NULL,            -- en français, sans jargon (US-17)
    condition       JSONB        NOT NULL,
    weight          SMALLINT     NOT NULL CHECK (weight BETWEEN 1 AND 100),
    severity        VARCHAR(16)  NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    window_seconds  INTEGER      NOT NULL DEFAULT 0,
    profile_hint    VARCHAR(32),
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    version         INTEGER      NOT NULL DEFAULT 1
);

CREATE TABLE rule_match (
    id                 BIGSERIAL PRIMARY KEY,
    rule_id            SMALLINT  NOT NULL REFERENCES detection_rule (id),
    session_id         UUID      NOT NULL REFERENCES session (id) ON DELETE CASCADE,
    event_id           BIGINT,
    matched_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    contributed_score  SMALLINT  NOT NULL CHECK (contributed_score >= 0)
);

-- Écran E6 : « nombre de déclenchements par règle sur 7 jours ».
CREATE INDEX rule_match_rule_id_idx ON rule_match (rule_id, matched_at DESC);
CREATE INDEX rule_match_session_idx ON rule_match (session_id);

-- -----------------------------------------------------------------------------
-- Alertes
-- -----------------------------------------------------------------------------
CREATE TABLE alert_channel (
    id           SMALLSERIAL PRIMARY KEY,
    type         VARCHAR(16) NOT NULL CHECK (type IN ('discord','email')),
    config       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    last_status  VARCHAR(16),
    last_sent_at TIMESTAMPTZ
);

CREATE TABLE alert (
    id            BIGSERIAL PRIMARY KEY,
    rule_id       SMALLINT REFERENCES detection_rule (id),
    channel_id    SMALLINT REFERENCES alert_channel (id),
    triggered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metric_value  NUMERIC,
    threshold     NUMERIC,
    status        VARCHAR(16) NOT NULL DEFAULT 'pending',
    muted_until   TIMESTAMPTZ
);

CREATE INDEX alert_triggered_at_idx ON alert (triggered_at DESC);

-- -----------------------------------------------------------------------------
-- blocklist_entry — liste d''adresses hostiles exploitable par un pare-feu (US-43).
-- -----------------------------------------------------------------------------
CREATE TABLE blocklist_entry (
    ip          INET        PRIMARY KEY REFERENCES ip_intel (ip) ON DELETE CASCADE,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    score       SMALLINT    NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX blocklist_expires_at_idx ON blocklist_entry (expires_at);

-- -----------------------------------------------------------------------------
-- Comptes et jetons — UN SEUL compte administrateur en v1.
-- -----------------------------------------------------------------------------
CREATE TABLE app_user (
    id             SMALLSERIAL PRIMARY KEY,
    username       VARCHAR(64)  NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at  TIMESTAMPTZ
);

CREATE TABLE api_token (
    id           SMALLSERIAL PRIMARY KEY,
    user_id      SMALLINT     NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    name         VARCHAR(64)  NOT NULL,
    token_hash   CHAR(64)     NOT NULL UNIQUE,
    scopes       VARCHAR(128) NOT NULL DEFAULT 'read',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- -----------------------------------------------------------------------------
-- Veille et sandbox
-- -----------------------------------------------------------------------------
CREATE TABLE cve_watch (
    cve_id          VARCHAR(24) PRIMARY KEY,
    published_at    TIMESTAMPTZ,
    cvss            NUMERIC(3,1),
    summary         TEXT,
    kev_flag        BOOLEAN     NOT NULL DEFAULT FALSE,
    matched_events  INTEGER     NOT NULL DEFAULT 0,
    last_matched_at TIMESTAMPTZ
);

CREATE TABLE sandbox_run (
    id              UUID        PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    attacker_label  VARCHAR(64),
    defender_label  VARCHAR(64),
    scenario        VARCHAR(64) NOT NULL DEFAULT 'libre',
    events_count    INTEGER     NOT NULL DEFAULT 0,
    detected_count  INTEGER     NOT NULL DEFAULT 0,
    detection_rate  SMALLINT
);

-- -----------------------------------------------------------------------------
-- event_rejected — les événements malformés. Tracés, jamais perdus (§ 4.1).
-- -----------------------------------------------------------------------------
CREATE TABLE event_rejected (
    id          BIGSERIAL   PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason      TEXT        NOT NULL,
    raw_body    BYTEA
);

-- -----------------------------------------------------------------------------
-- retention_job — journal des purges RGPD (US-46).
-- -----------------------------------------------------------------------------
CREATE TABLE retention_job (
    id            BIGSERIAL   PRIMARY KEY,
    ran_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cutoff_date   DATE        NOT NULL,
    partition     VARCHAR(64),
    deleted_rows  BIGINT      NOT NULL DEFAULT 0
);

COMMIT;