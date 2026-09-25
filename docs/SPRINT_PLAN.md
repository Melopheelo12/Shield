# Plan de sprints — Étape 4

> Livrable de la tâche 0 de l'étape 4. Découpage des 49 user stories de l'étape 3
> en tâches exécutables, avec dépendances, responsables et échéances.

## 1. Cadre

| Élément | Valeur |
| :--- | :--- |
| Durée d'un sprint | **1 semaine**, du lundi 9 h au vendredi 17 h |
| Nombre de sprints | 5 (sprint 0 de préparation + 4 sprints de développement) |
| Équipe | Ryan (back-end & sécurité) · Antho (front-end & DevOps) |
| Capacité | ~25 h par personne et par semaine, soit **~50 h par sprint** |
| Unité d'estimation | Le **point** : 1 point ≈ 2 h de travail effectif. Capacité ≈ 24 points/sprint |
| Outil de suivi | GitHub Projects (colonnes *Backlog / À faire / En cours / En revue / Terminé*) |

### Rôles non techniques, par sprint

Les rôles tournent pour que chacun les pratique — c'est explicitement évalué à la
revue technique.

| Sprint | Project Manager | Source Control Manager | Quality Assurance |
| :---: | :--- | :--- | :--- |
| 0 | Ryan | Antho | Antho |
| 1 | Ryan | Antho | Antho |
| 2 | Antho | Ryan | Antho |
| 3 | Antho | Ryan | Ryan |
| 4 | Ryan | Antho | Ryan |

**Le QA n'est jamais celui qui a écrit le code recetté.** C'est la règle « personne ne
recette son propre code » de l'étape 1, appliquée sprint par sprint.

| Rôle | Ce qu'il fait concrètement chaque semaine |
| :--- | :--- |
| **PM** | Anime le planning du lundi, tient le board à jour, calcule la vélocité, décide des arbitrages, rédige le compte rendu de revue |
| **SCM** | Garde `main` propre : relit chaque PR, fait respecter Conventional Commits et la taille des PR, pose les étiquettes de version, gère les conflits |
| **QA** | Rédige le plan de test du sprint, recette les stories terminées contre leurs critères d'acceptation, ouvre les issues de bug, tient le tableau des bugs |

## 2. Rituels

| Rituel | Quand | Durée | Livrable |
| :--- | :--- | :---: | :--- |
| Planification | Lundi 9 h 00 | 30 min | Objectif de sprint, issues affectées, capacité vérifiée |
| Point quotidien | Chaque jour avant 10 h, écrit sur Discord | 5 min | 3 lignes : fait hier / prévu aujourd'hui / bloqué par |
| Point technique | Mercredi 18 h 00 | 20 min | Décisions d'architecture, ADR si structurante |
| Revue de sprint | Vendredi 17 h 00 | 25 min | Démonstration de l'incrément + compte rendu (`docs/sprints/`) |
| Rétrospective | Vendredi 17 h 30 | 20 min | **Une seule action d'amélioration**, affectée et datée |
| Point mentor | Hebdomadaire | 30 min | Validation du jalon, arbitrages |

## 3. Vue d'ensemble

| Sprint | Semaine | Objectif — en une phrase | Jalon | Points |
| :---: | :---: | :--- | :---: | :---: |
| **0** | S6 | Le dépôt, la CI et le serveur existent ; le premier leurre collecte des attaques réelles | J4 | 20 |
| **1** | S7 | Les trois leurres capturent sans perte et les données sont en base | J5 | 24 |
| **2** | S8 | Chaque événement est enrichi et qualifié par l'agent défenseur | J6 | 24 |
| **3** | S9 | Le tableau de bord affiche les données en direct | — | 24 |
| **4** | S10 | Alertes, options retenues, recette croisée, produit démontrable | J7 | 22 |

**Le sprint 0 est le plus rentable du projet.** Chaque jour gagné sur la mise en ligne
du serveur est un jour de données réelles en plus pour la soutenance. Il est donc
prioritaire sur tout le reste.

---

## Sprint 0 — Fondations (S6) · Jalon J4

**Objectif :** *à la fin de la semaine, une attaque réelle arrive depuis Internet et
finit dans nos journaux.*

| # | Tâche | Story | Resp. | Pts | Dépend de |
| :--- | :--- | :---: | :---: | :---: | :--- |
| S0-01 | Créer le dépôt, la structure, `pyproject.toml`, `.gitignore`, licence | — | Antho | 1 | — |
| S0-02 | Protéger `main` : PR obligatoire, 1 approbation, CI verte, historique linéaire | — | Antho | 1 | S0-01 |
| S0-03 | Créer les 49 issues depuis le backlog + labels + board | — | Ryan | 2 | S0-01 |
| S0-04 | **Figer le contrat d'événement** (`common/schema.py`) et le faire relire | US-01 | Ryan | 2 | S0-01 |
| S0-05 | **Générateur d'événements factices** — débloque la lane front | — | Ryan | 2 | S0-04 |
| S0-06 | Génération des types TypeScript + vérification en CI | — | Ryan | 2 | S0-04 |
| S0-07 | Pipeline CI : lint, tests, sécurité, build | — | Antho | 3 | S0-01 |
| S0-08 | `docker-compose.yml` avec les 5 réseaux, `decoy_net` en `internal` | US-05 | Antho | 3 | S0-01 |
| S0-09 | **Louer le VPS et vérifier les conditions d'utilisation de l'hébergeur** | — | Antho | 1 | — |
| S0-10 | Durcir le serveur : SSH sur clé et port décalé, pare-feu, mises à jour auto, aucun secret | US-49 | Ryan | 3 | S0-09 |
| S0-11 | **Mettre le leurre SSH en ligne** et vérifier l'arrivée du premier événement | US-01, US-02 | Ryan | 2 | S0-08, S0-10 |
| S0-12 | Squelette du tableau de bord (Vite + React + TS) branché sur le générateur | — | Antho | 2 | S0-06 |
| S0-13 | README avec architecture et modèle de données | — | Antho | 1 | — |

**Total : 25 points.** Légèrement au-dessus de la capacité : S0-12 et S0-13 sont les
variables d'ajustement.

**Critère de sortie (J4) :** le serveur est en ligne, durci, un leurre collecte, la CI
est verte sur `main`, et Antho développe le tableau de bord sans dépendre de Ryan.

> **Point de vigilance.** S0-09 (conditions de l'hébergeur) est sans dépendance et
> peut tout bloquer. À faire **lundi matin**, pas vendredi.

---

## Sprint 1 — Capture (S7) · Jalon J5

**Objectif :** *les trois leurres capturent 100 % des tentatives, sans perte jusqu'à
50 événements par seconde, et tout est en base.*

| # | Tâche | Story | Resp. | Pts | Dépend de |
| :--- | :--- | :---: | :---: | :---: | :--- |
| S1-01 | Leurre HTTP : fausse page d'administration, analyse des soumissions | US-01, US-03 | Ryan | 3 | S0-11 |
| S1-02 | Leurre FTP : séquence USER / PASS | US-01, US-03 | Ryan | 2 | S0-11 |
| S1-03 | Bannières configurables et versionnées pour les trois leurres | US-02 | Ryan | 1 | S1-01 |
| S1-04 | `SessionTracker` : fenêtre d'inactivité de 5 min | US-04 | Ryan | 2 | S0-04 |
| S1-05 | **Modèles SQLAlchemy + migration initiale** (event partitionnée, session, ip_intel…) | — | Ryan | 4 | S0-08 |
| S1-06 | **Brancher le collecteur sur PostgreSQL** (remplace l'entrepôt en mémoire) | — | Ryan | 3 | S1-05 |
| S1-07 | Conservation de la charge utile plafonnée + empreinte SHA-256 | US-06 | Ryan | 2 | S1-05 |
| S1-08 | **Test de charge : 3 000 événements en 60 s, zéro perte** | US-01 | Antho (QA) | 2 | S1-06 |
| S1-09 | Jeu de tests d'entrées malveillantes (binaire, UTF-8 invalide, XSS, SQLi) | US-01 | Antho (QA) | 2 | S1-06 |
| S1-10 | Test d'isolation : depuis un leurre, toute sortie Internet échoue | US-05 | Antho (QA) | 2 | S0-08 |
| S1-11 | Composants du tableau de bord : tableau d'événements + barre de filtres | US-27 | Antho | 3 | S0-12 |

**Total : 26 points.** S1-11 est la variable d'ajustement.

**Critère de sortie (J5) :** les tentatives sont capturées sans perte — recette croisée
par Antho, sur les critères d'acceptation de US-01 à US-06.

---

## Sprint 2 — Enrichissement et agent défenseur (S8) · Jalon J6

**Objectif :** *chaque événement arrive qualifié : pays, opérateur, réputation,
technique ATT&CK, score de menace et profil d'attaquant.*

| # | Tâche | Story | Resp. | Pts | Dépend de |
| :--- | :--- | :---: | :---: | :---: | :--- |
| S2-01 | `GeoIpEnricher` : base GeoLite2 locale, pays + ASN, hors ligne | US-07 | Ryan | 3 | S1-06 |
| S2-02 | `ReputationEnricher` : AbuseIPDB + cache Redis 24 h | US-08 | Ryan | 3 | S1-06 |
| S2-03 | **Dégradation gracieuse** : quota, délai, panne → `pending` puis reprise | US-10 | Ryan | 3 | S2-02 |
| S2-04 | `MitreMapper` : table de correspondance testée unitairement | US-09 | Ryan | 2 | S1-06 |
| S2-05 | Enrichissement asynchrone hors du chemin d'ingestion (< 2 s médian) | US-11 | Ryan | 2 | S2-01 |
| S2-06 | **Moteur de règles** : chargement YAML, évaluation, rechargement à chaud | US-12, US-16 | Ryan | 4 | S1-06 |
| S2-07 | Compteurs de fenêtre glissante dans Redis | US-18 | Ryan | 2 | S2-06 |
| S2-08 | Scoring plafonné + contributions qui somment au score | US-13 | Ryan | 2 | S2-06 |
| S2-09 | Profilage de l'attaquant (liste fermée) | US-14 | Ryan | 2 | S2-08 |
| S2-10 | **Test de reproductibilité du verdict** sur un jeu figé | US-15 | Antho (QA) | 2 | S2-08 |
| S2-11 | Test de dégradation gracieuse (API tierce simulée en échec) | US-10 | Antho (QA) | 2 | S2-03 |
| S2-12 | Carte mondiale + chronologie sur données factices | US-21, US-22 | Antho | 4 | S1-11 |

**Total : 31 points — au-dessus de la capacité.** C'est le sprint le plus chargé et il
faut le dire maintenant, pas le vendredi. Arbitrage prévu : S2-09 et S2-12 glissent au
sprint 3 si nécessaire.

**Critère de sortie (J6) :** les données sont enrichies automatiquement et l'agent
produit un verdict explicable et reproductible.

---

## Sprint 3 — Tableau de bord temps réel (S9)

**Objectif :** *une attaque capturée apparaît à l'écran en moins de cinq secondes.*

| # | Tâche | Story | Resp. | Pts | Dépend de |
| :--- | :--- | :---: | :---: | :---: | :--- |
| S3-01 | Authentification JWT + ralentissement après 5 échecs | US-19 | Ryan | 3 | S1-06 |
| S3-02 | Publication Redis + point d'entrée WebSocket | US-20 | Ryan | 3 | S2-08 |
| S3-03 | Points d'entrée de statistiques (overview, timeline, tops, by-service) | US-23 → US-25 | Ryan | 3 | S2-08 |
| S3-04 | Détail de session + **règles déclenchées** | US-26, US-13 | Ryan | 3 | S2-08 |
| S3-05 | Écran de connexion | US-19 | Antho | 1 | S3-01 |
| S3-06 | `useWebSocket` : reconnexion automatique, état visible | US-20 | Antho | 3 | S3-02 |
| S3-07 | Vue d'ensemble : 4 cartes de statistique + flux temps réel | US-20 | Antho | 3 | S3-03 |
| S3-08 | Les 5 visualisations obligatoires | US-21 → US-25 | Antho | 4 | S3-03 |
| S3-09 | Tiroir de détail de session + contributions des règles | US-26 | Antho | 3 | S3-04 |
| S3-10 | Responsive 375 px, états vide / chargement / erreur | US-28 | Antho | 3 | S3-07 |
| S3-11 | **Mesure de latence sur 20 événements consécutifs (< 5 s)** | US-20 | Ryan (QA) | 1 | S3-06 |

**Total : 30 points — au-dessus de la capacité.**

> ### Point d'arbitrage — vendredi fin de S9
>
> **Si le tableau de bord n'affiche pas les données en direct à cette date**, le
> scénario dégradé du § 7.6 de la documentation technique s'applique, dans cet ordre :
> thème sombre et jetons d'API → agent de veille → sandbox → export et liste de blocage
> → alertes par courriel → réduction à 3 visualisations.
>
> Cette décision est écrite à l'avance précisément pour ne pas avoir à la prendre dans
> l'urgence.

---

## Sprint 4 — Alertes, options et recette (S10) · Jalon J7

**Objectif :** *le produit est complet, recetté, démontrable. Plus aucune nouvelle
fonctionnalité après ce point.*

Ce sprint est un **sprint d'options** : on prend dans l'ordre, et on arrête quand la
semaine est pleine. Le MVP est complet sans aucune option.

| Ordre | # | Tâche | Story | Resp. | Pts |
| :---: | :--- | :--- | :---: | :---: | :---: |
| 1 | S4-01 | Gestionnaire d'alertes : seuils, période de silence, webhook Discord | US-30, US-31 | Ryan | 4 |
| 1 | S4-02 | Interface de configuration des alertes | US-31 | Antho | 3 |
| 1 | S4-03 | **Test d'unicité : un franchissement = une alerte** | US-30 | Ryan (QA) | 2 |
| 2 | S4-04 | Purge automatique + pseudonymisation à l'export | US-46, US-47 | Ryan | 3 |
| 2 | S4-05 | Procédure d'arrêt d'urgence, **documentée et testée** | US-48 | Ryan | 1 |
| 3 | S4-06 | Export CSV / JSON par lots | US-42 | Ryan | 2 |
| 3 | S4-07 | Point d'entrée liste de blocage (`text/plain`) | US-43 | Ryan | 1 |
| 4 | S4-08 | Sandbox : compose isolé, CLI, garde-fou `SHIELD_ENV` | US-34, US-35, US-38 | Antho | 4 |
| 4 | S4-09 | Rapport de fin de partie (taux de détection) | US-37 | Ryan | 2 |
| 5 | S4-10 | Alertes par courriel | US-32 | Ryan | 2 |
| 5 | S4-11 | Agent de veille CVE / KEV + corrélation | US-39 → US-41 | Ryan | 4 |
| 6 | S4-12 | Écran des règles de détection | US-16, US-17 | Antho | 2 |
| 6 | S4-13 | Thème sombre | US-33 | Antho | 1 |
| — | S4-14 | **Recette croisée complète sur les 33 stories Must** | toutes | Les deux | 4 |
| — | S4-15 | Tests de bout en bout Playwright sur les 4 parcours | — | Antho (QA) | 3 |

**Engagement ferme :** ordres 1 et 2 + S4-14 + S4-15 = **20 points**. Le reste est pris
si la semaine le permet.

**Critère de sortie (J7) :** le produit est complet et démontrable ; plus aucune
nouvelle fonctionnalité n'est acceptée après ce point.

---

## 4. Chemin critique

```
Contrat d'événement (S0-04)
   └─> Serveur en ligne (S0-11)
          └─> Capture 3 leurres + base (S1-06)
                 └─> Enrichissement (S2-01..05)
                        └─> Agent défenseur (S2-06..09)
                               └─> Temps réel (S3-02, S3-06)
                                      └─> Soutenance
```

Tout ce qui n'est pas sur ce chemin — export, liste de blocage, alertes par courriel,
veille, sandbox, thème sombre — est **sacrifiable**. Tout retard sur le chemin critique
se répercute intégralement sur la suite.

## 5. Ce qui débloque le travail en parallèle

Deux artefacts, et deux seulement, permettent aux lanes de Ryan et d'Antho d'avancer
sans s'attendre :

1. **Le contrat d'événement** (S0-04), figé et versionné.
2. **Le générateur d'événements factices** (S0-05), qui laisse Antho construire tout le
   tableau de bord sans que la capture existe.

Sans eux, les deux lanes travaillent en série et le projet prend une semaine de retard
structurel. C'est pourquoi ils sont en sprint 0 et non en sprint 1.
