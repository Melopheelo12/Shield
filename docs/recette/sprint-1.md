# Recette croisée — Sprint 1

**QA :** Antho · **Périmètre recetté :** celui de Ryan (`US-01` → `US-06`)
**Version :** `feat/postgres-repository` @ `5f97bb9` (PR #51), PostgreSQL 16
**Dates :** 4 et 6 octobre 2026

Chaque ligne se rejoue avec `make qa-*` (voir `scripts/qa/`).

## Verdict J5

> **Les tentatives sont-elles capturées sans perte, et persistées ?**
> **Oui pour les événements**, **non pour les sessions** (#58). J5 est donc validé sous réserve.

| Critère | Résultat | Preuve |
| --- | --- | --- |
| 3 000 événements en 60 s, comptés **en base**, zéro perte | ✅ | 3 000 envoyés en 60,0 s · `select count(*) from event` = **3 000** · 0 rejeté · p50 16 ms, p95 22 ms, max 59 ms |
| Redémarrage du collecteur : les 3 000 sont toujours là | ✅ | `/api/v1/stats/overview` = 3 000 avant **et** après |
| Les sessions survivent au redémarrage | ❌ | #58 — une IP active ouvre une 2ᵉ session ; l'ancienne ne se ferme jamais |
| Entrées malveillantes : tout stocké inerte, rien interprété | ✅ | 19 tentatives → 19 lignes ; XSS et SQL stockés comme texte ; table `event` intacte ; aucune entrée reflétée |
| Octets NUL (incompatibles avec `text`) | ✅ | Neutralisés par `postgres.py` (`\x00` → `�`) |
| Le service ne tombe pas | ✅ | Leurres et collecteur vivants après la salve |
| Jamais de 5xx | ❌ | #54 — JSON très imbriqué → 500 (exposition faible : jeton requis, nginx renvoie 404) |
| FTP : identifiants séparés quand USER et PASS arrivent ensemble | ❌ | #53 |
| Isolation : toute sortie échoue depuis un leurre | ✅ | TCP, UDP, DNS, HTTP, hôte : bloqués ×3 ; seul `collector:8000` répond |
| Aucune fuite d'identité | ✅ | 43 sondes, 0 occurrence de « shield », « honeypot », « python »… |
| Ports des leurres publiés sur l'hôte | ❌ | #52 — **bloquant pour J4** |

## Schéma PostgreSQL (US-04)

Conforme au plan : `event` partitionnée par mois sur `occurred_at` (`event_2026_10`,
`event_2026_11`) ; `source_ip` en `INET` sur `event`, `session` et `ip_intel` ; index
`(occurred_at DESC)`, `(source_ip, occurred_at DESC)`, `(session_id)`,
`(service_id, occurred_at DESC)` et l'index partiel `(threat_score DESC) WHERE closed`
sur `session` ; jeu de départ : 3 services, 7 techniques ATT&CK.

## Écarts ouverts

| Issue | Gravité | Résumé |
| --- | --- | --- |
| #52 | bloquant | Ports des leurres non publiés (réseaux `internal`) — J4 impossible |
| #58 | majeur | Sessions perdues au redémarrage du collecteur |
| #53 | majeur | FTP : USER + PASS dans un même paquet → mot de passe perdu |
| #54 | mineur | HTTP 500 sur JSON très imbriqué |
| #55 | mineur | `make load` plafonne à ~36 évén./s ; remplacé en recette par `make qa-load` |

## Hors recette

- Leurres HTTP / FTP en conditions réelles et `nmap -sV` (jeudi de Ryan),
  stockage de la charge avec empreinte SHA-256 (vendredi) : **aucune branche
  poussée** au moment de la recette.
- Premier événement réel venu d'Internet : impossible sans VPS ni correction de #52.

## Rejouer la recette

```bash
docker run -d --name pg -e POSTGRES_USER=shield -e POSTGRES_PASSWORD=shield \
  -e POSTGRES_DB=shield -p 5432:5432 postgres:16-alpine
for f in deploy/initdb/*.sql; do docker exec -i pg psql -U shield -d shield < "$f"; done
make run-api                       # SHIELD_STORAGE=postgres
make run-decoy                     # et les leurres http (8080) / ftp (2121)
make qa                            # charge + entrées malveillantes + fuites d'identité
docker compose up -d && make qa-egress
```

## Suivi au 8 octobre 2026

Revérifié sur `main` après les correctifs de Ryan, pile complète avec le relais
d'entrée (ADR 008).

| Issue | État | Vérification |
| --- | --- | --- |
| #52 | levé par #67 | Ports publiés par `edge`, adresse réelle transmise par PROXY protocol, leurres toujours isolés (`make qa-egress` : 0 écart). Régression de demi-fermeture trouvée et corrigée par #70. À fermer après vérification sur le VPS. |
| #58 | corrigé par #66 | — |
| #62 | corrigé par #64 | — |
| #63 | corrigé par #65 | JSON illisible sans jeton → 401 |
| #53 | correctif en revue (#68) | Toujours reproduit sur `main` |
| #54 | ouvert | 500 avec jeton en local (Python 3.14) ; non reproduit dans l'image Docker (Python 3.12) |
| #55 | ouvert | Contourné par `make qa-load` |

Via le relais : 19 tentatives → 19 événements, 43 sondes → 0 fuite d'identité.
