-- =============================================================================
-- SHIELD — seuils d'alerte configurables (US-30, US-31, S4-01)
--
-- Exécuté après 003_enrichment.sql au premier démarrage. Purement additif et
-- idempotent : peut être appliqué à la main sur une base existante.
--
--   psql "$DATABASE_URL" -f deploy/initdb/004_alerting.sql
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- alert_threshold — les seuils modifiables depuis l'interface (US-31).
-- Une table vide signifie « jamais configuré » : le collecteur y écrit alors
-- les seuils par défaut au démarrage.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_threshold (
    id               VARCHAR(32) PRIMARY KEY,
    metric           VARCHAR(32) NOT NULL
                     CHECK (metric IN ('events', 'unique_ips', 'max_threat_score')),
    threshold        NUMERIC     NOT NULL CHECK (threshold > 0),
    window_seconds   INTEGER     NOT NULL CHECK (window_seconds BETWEEN 1 AND 86400),
    silence_seconds  INTEGER     NOT NULL CHECK (silence_seconds BETWEEN 0 AND 604800),
    enabled          BOOLEAN     NOT NULL DEFAULT TRUE
);

-- -----------------------------------------------------------------------------
-- alert — une ligne par franchissement. `rule_id` reste pour une alerte issue
-- d'une règle de détection ; une alerte de seuil porte `threshold_key`.
-- `channels` : résultat par canal, {"discord": "sent", "email": "failed"}.
-- -----------------------------------------------------------------------------
ALTER TABLE alert ADD COLUMN IF NOT EXISTS threshold_key VARCHAR(32);
ALTER TABLE alert ADD COLUMN IF NOT EXISTS channels JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMIT;
