# Tests d'intégration

Ces tests exigent PostgreSQL et Redis réels. Ils tournent en CI via les *services*
GitHub Actions (voir `.github/workflows/ci.yml`, job `integration`), et localement via
`docker compose up -d postgres redis`.

Ils sont écrits au **sprint 1**, en même temps que le branchement du collecteur sur
PostgreSQL (tâches S1-05 et S1-06 du plan de sprints).

## Ce qu'ils doivent couvrir

| Test | Exigence vérifiée |
| :--- | :--- |
| Ingestion → base → enrichissement → verdict | Chaîne complète sur une vraie base |
| Partition mensuelle créée automatiquement | Purge RGPD par `DROP PARTITION` |
| Purge de conservation | US-46 |
| Reprise d'enrichissement `pending` | US-10, dégradation gracieuse |
| Compteurs Redis de fenêtre glissante | US-18 |
| Unicité de l'alerte sur franchissement prolongé | US-30 |
| Isolation réseau : sortie depuis un leurre refusée | US-05 |
