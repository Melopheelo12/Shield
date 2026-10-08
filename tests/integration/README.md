# Tests d'intégration

Ces tests exigent PostgreSQL et Redis réels. Ils tournent en CI via les *services*
GitHub Actions (voir `.github/workflows/ci.yml`, job `integration`), et localement via
`docker compose up -d postgres redis`.

## Lancer en local

```bash
make test-integration          # utilise DATABASE_URL, défaut : shield:shield@localhost:5432/shield
```

Chaque test crée un **schéma jetable** (`shield_it_…`), y applique les scripts de
`deploy/initdb/` puis le supprime : la base visée n'est jamais modifiée ailleurs, on
peut donc viser sa base de développement. Sans PostgreSQL joignable, les tests sont
ignorés ; avec `SHIELD_REQUIRE_DB=1` (positionné en CI), ils échouent.

## Ce qu'ils doivent couvrir

| Test | Exigence vérifiée | État |
| :--- | :--- | :---: |
| Ingestion → base → verdict, par l'API | Chaîne complète sur une vraie base (S1-06) | ✅ |
| Écriture / relecture d'un événement, verdict identique | US-01, US-13 | ✅ |
| Rejet tracé dans `event_rejected` | § 4.1 | ✅ |
| Événement rangé dans sa partition mensuelle | Partitionnement (ADR 004) | ✅ |
| Ingestion → base → enrichissement → verdict | Chaîne complète avec enrichissement | |
| Partition mensuelle créée automatiquement | Purge RGPD par `DROP PARTITION` | |
| Purge de conservation | US-46 |
| Reprise d'enrichissement `pending` | US-10, dégradation gracieuse |
| Compteurs Redis de fenêtre glissante | US-18 |
| Unicité de l'alerte sur franchissement prolongé | US-30 |
| Isolation réseau : sortie depuis un leurre refusée | US-05 |
