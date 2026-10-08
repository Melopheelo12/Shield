-- =============================================================================
-- SHIELD — identité contractuelle de l'événement et profil par événement
--
-- Exécuté après 001_schema.sql au premier démarrage. Purement additif : peut
-- aussi être appliqué à la main sur une base existante (idempotent).
--
--   psql "$DATABASE_URL" -f deploy/initdb/002_event_identity.sql
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- event.event_uid — l'identifiant du contrat (``RawEvent.event_id``).
--
-- `event.id` est un BIGSERIAL interne ; le tableau de bord et l'API, eux, ne
-- connaissent que l'UUID émis par le leurre (GET /events/{event_id}/verdict).
-- NOT NULL sans valeur par défaut : aucune version antérieure du collecteur
-- n'écrivait dans `event`, la table est donc vide quand ce script s'applique.
--
-- Pas de contrainte UNIQUE : sur une table partitionnée elle devrait inclure
-- occurred_at et ne garantirait donc rien. L'unicité vient de l'UUID v4.
-- -----------------------------------------------------------------------------
ALTER TABLE event ADD COLUMN IF NOT EXISTS event_uid UUID NOT NULL;
CREATE INDEX IF NOT EXISTS event_event_uid_idx ON event (event_uid);

-- -----------------------------------------------------------------------------
-- event.attacker_profile — le profil du verdict, par événement (US-14).
--
-- `session.attacker_profile` ne garde que le profil du pire événement de la
-- session ; relire le verdict d'un événement précis exige le sien.
-- -----------------------------------------------------------------------------
ALTER TABLE event
    ADD COLUMN IF NOT EXISTS attacker_profile VARCHAR(32) NOT NULL DEFAULT 'indetermine';

-- -----------------------------------------------------------------------------
-- create_event_partition — teste l'existence via to_regclass, qui respecte le
-- search_path, au lieu de pg_class.relname, qui ignore le schéma. Sans cela,
-- une partition homonyme dans un autre schéma (tests d'intégration) empêche
-- la création.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION create_event_partition(target DATE)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    start_date DATE := date_trunc('month', target)::DATE;
    end_date   DATE := (date_trunc('month', target) + INTERVAL '1 month')::DATE;
    part_name  TEXT := 'event_' || to_char(start_date, 'YYYY_MM');
BEGIN
    IF to_regclass(quote_ident(part_name)) IS NOT NULL THEN
        RETURN part_name || ' (existe deja)';
    END IF;
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF event FOR VALUES FROM (%L) TO (%L)',
        part_name, start_date, end_date
    );
    RETURN part_name || ' (creee)';
END;
$$;

SELECT create_event_partition(CURRENT_DATE);
SELECT create_event_partition((CURRENT_DATE + INTERVAL '1 month')::DATE);

COMMIT;
