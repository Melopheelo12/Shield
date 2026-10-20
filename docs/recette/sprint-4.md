# Recette croisée — Sprints 2 à 4 (périmètre de Ryan)

**QA :** Antho · **Périmètre recetté :** PR #81 à #86 de Ryan
**Version :** `main` @ `416f167` (avec #86) fusionnée localement avec #81 `b91c08e`,
#82 `e3b63c9` (avec #85), #83 `a536c9d`, #84 `5012cb4` — sans conflit
**Base :** PostgreSQL 16 (jetable) pour la persistance, mémoire pour les parcours d'interface
**Dates :** 14 et 15 octobre 2026

Les recettes d'interface (connexion, temps réel, chronologie, carte, session, liste de
blocage, export, sandbox, alertes) sont décrites en détail dans les PR #87 à #95, et
rejouées en continu par les quatre parcours Playwright de #98 (`make e2e`).

## Verdict

> **Le back-end des sprints 2 à 4 tient ses critères d'acceptation**, à deux bugs près,
> ouverts pendant la recette : **#99** (la défense active peut couper le leurre SSH, déjà
> dans `main`) et **#100** (fenêtre de perte à l'archivage). #54 reste ouvert.

## Ensemble

| Critère | Résultat | Preuve |
| --- | --- | --- |
| Les six PR se fusionnent ensemble | ✅ | Aucun conflit · 376 tests unitaires et 23 tests d'intégration (PostgreSQL) verts |
| 3 000 événements en 60 s, zéro perte | ✅ | 3 000 / 3 000 en base · p50 17 ms, p95 23 ms, max 48 ms |
| Enrichissement terminé hors du chemin d'ingestion | ✅ | 0 événement resté `pending` après la charge (adresses de documentation) |
| Entrées malveillantes : rien reflété, tout stocké inerte | ✅ | `make qa-inputs` : 1 seul écart, #54 (connu) · octets NUL neutralisés sur PostgreSQL |
| Aucune fuite d'identité (y compris le nouveau leurre WordPress) | ✅ | `make qa-identity` : 43 sondes, 0 fuite, 0 sans réponse |

## Par story

| Story | Critère | Résultat | Preuve |
| --- | --- | --- | --- |
| S3-01 · US-19 | Toute consultation exige un jeton | ✅ | `/events`, `/watch`… sans jeton → 401 ; `/health` reste public |
| S3-01 · US-19 | Ralentissement après 5 échecs | ✅ | 6ᵉ essai → 429 et `Retry-After: 30`, affiché à l'écran (#87) |
| #81 | nginx démarre avec la limite de connexion | ✅ | `nginx -t` dans `nginx:1.27-alpine` : `syntax is ok` |
| S3-02 · US-20 | Attaque à l'écran en moins de 5 s | ✅ | **75 ms** entre l'ingestion et l'affichage (#88) |
| S3-03 | Statistiques exactes au-delà de 500 événements | ✅ | 1 346 tentatives : API = chronologie = carte = vue d'ensemble (#89, #90) |
| S3-04 · US-26 | Détail de session et règles agrégées | ✅ | Session de 2 tentatives, R-001 ×2 +40, R-002 ×1 +15 (#91) |
| S2-03 · US-10 | **Dégradation gracieuse** (S2-11, test d'Antho) | ✅ | AbuseIPDB rendu injoignable (proxy mort, rien ne sort) : 100 / 100 acceptées en 202, p95 6,6 ms, événements `pending`, AbuseIPDB suspendu 60 s. Reprise : couverte par les tests unitaires, non rejouée (l'URL n'est pas configurable) |
| S2-01 · US-07 | Pays et ASN par GeoLite2 | ⏳ | Sans base : tout est « non situé » et annoncé. À vérifier sur le VPS avec #96 et un compte MaxMind |
| #83 · US-12 | Objectif de 80 % de détection | ✅ | Générateur, 2 000 événements : **100 %** (78 % sans #83) · Log4Shell : score 86, T1190 |
| #84 | Le leurre HTTP passe pour un WordPress | ✅ | `/` 200, `/wp-admin/` 302 vers la connexion, `/xmlrpc.php` 405, `/?author=1` 301 vers `atelier`, `/.env` et le reste 404 · `Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4.33` |
| #84 · R-020 | L'utilisateur appât trahit une attaque ciblée | ✅ | `log=atelier` sur `wp-login.php` : identifiants capturés, score 35 (R-019 5 + R-020 30) |
| S4-01 · US-30 | Alerte Discord au franchissement | ✅ | Faux webhook local : message reçu, historique `volume · 5 / 5 · envoyée · discord ✓` (#95) |
| S4-03 | **Un franchissement = une alerte** | ✅ | 2 000 tentatives au-dessus d'un seuil de 50 → **1** alerte, **1** message Discord |
| S4-02 · US-31 | Seuils modifiables et conservés | ✅ | Valeur conservée au rechargement · « Tester » → `discord : sent` |
| S4-10 · US-32 | Alerte par courriel | ⏳ | Non rejouée : pas de serveur SMTP de recette |
| S4-04 · US-47 | Export pseudonymisé, jamais silencieux | ✅ | `192.0.2.123` → `192.0.2.0`, colonne `password` absente, mode lu dans `X-Shield-Pseudonymized` et affiché |
| S4-06 · US-42 | Export CSV / JSON par lots | ✅ | 1 346 lignes, en clair comme en pseudonymisé |
| S4-07 · US-43 | Liste de blocage en `text/plain` | ✅ | ≥ 60 : 68 adresses ; ≥ 30 : 399 — identique à l'écran (#92) |
| S4-09 · US-37 | Rapport de partie | ✅ | 54 tentatives, 42 détectées, 78 %, techniques manquées : identique à l'écran (#93) |
| S4-11 · US-39 → 41 | Veille KEV et corrélation | ✅ | Catalogue CISA chargé (44 entrées récentes) · `/watch/CVE-2021-44228/events` : 33 événements corrélés |
| #85 · US-46 | Archivage sûr, purge des archives | ⚠️ | Tests d'intégration verts · **#100** : un événement inséré entre comptage et suppression serait perdu ; archive non synchronisée sur disque |
| #86 · ADR 011 | Défense active sans neutraliser le honeypot | ❌ | Test pare-feu de la PR vert, mais **#99** : la chaîne `forward` voit le port après DNAT ; avec l'exemple fourni (`2222`), les adresses bloquées perdent le leurre SSH |

## Points d'attention (pas des bugs)

- **Veille** : la liste ne garde que 44 entrées récentes du KEV. Une CVE ancienne mais
  très exploitée (Log4Shell) est bien corrélée par `/watch/{cve}/events`, mais n'apparaît
  pas comme « observée » dans la liste.
- **Lien des notifications** : `DASHBOARD_URL/?since_seconds=300` ouvre la vue d'ensemble,
  qui ne filtre pas. À aligner avec le journal (signalé dans #95).
- **Tableau de bord sur 8443** : `harden_vps.sh` ne le rend joignable que par tunnel SSH.
  Un accès par `https://<domaine>:8443` serait une décision d'équipe (signalé dans #97).

## Outils

`scripts/qa/malicious_inputs.py` lisait les statistiques sans jeton : il se connecte
désormais avec `--admin-user` / `--admin-password` (par défaut `ADMIN_PASSWORD`, puis le
compte de `make dev`), et reste compatible avec un collecteur sans authentification.

## Non vérifié ici

Tout ce qui demande le VPS : GeoLite2 avec un vrai compte, le domaine et le leurre HTTPS
(#97), la recette de #86 en conditions réelles (à refaire après #99), l'envoi Discord réel
et le courriel.
