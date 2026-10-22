-- =============================================================================
-- SHIELD — enrichissement différé (S2-03, S2-05, ADR 007)
--
-- Exécuté après 002_event_identity.sql au premier démarrage. Purement additif et
-- idempotent : peut être appliqué à la main sur une base existante.
--
--   psql "$DATABASE_URL" -f deploy/initdb/003_enrichment.sql
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- La tâche de fond cherche les événements dont l'enrichissement n'est pas
-- terminé. Ils sont une infime minorité : un index partiel reste minuscule et
-- évite de parcourir toute la table à chaque tour.
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS event_enrichment_pending_idx
    ON event (source_ip, occurred_at)
    WHERE enrichment_status <> 'done';

COMMIT;
