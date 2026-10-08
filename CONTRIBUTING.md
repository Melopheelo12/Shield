# Contribuer à SHIELD

> **Ce fichier fait autorité sur la façon de travailler dans ce dépôt.** Il vaut pour
> Ryan, pour Antho, et pour tout outil d'aide au développement, qui doit le lire avant
> de proposer la moindre modification. Ce qui est écrit ici l'emporte sur une habitude
> personnelle ou sur une convention apportée d'ailleurs.
>
> Il se tient à jour : une décision structurante absente d'ici sera reprise à zéro la
> fois suivante.

**SHIELD** — *Sandbox & Honeypot for Intelligent Engagement, Learning & Defense* :
un honeypot à faible interaction qui expose trois leurres (SSH, HTTP, FTP), enregistre
chaque tentative d'intrusion, la qualifie par un moteur de règles explicable, et
l'affiche sur un tableau de bord. Projet de fin de formation de **Ryan** (back-end et
sécurité) et **Antho** (front-end et DevOps).

## Mise en route

```bash
make install     # venv + dépendances + crochets de pre-commit
cp .env.example .env
make check       # tout ce que la CI vérifie
```

Les tests d'intégration exigent un PostgreSQL réel : `docker compose up -d postgres`,
ou une installation native suivie de l'application de `deploy/initdb/*.sql` dans
l'ordre et de l'export de `DATABASE_URL`. Sans base joignable, ils sont **ignorés** et
non en échec — sauf en CI, où `SHIELD_REQUIRE_DB=1` les rend bloquants.

> Avec Docker, les fichiers de `deploy/initdb/` ne sont exécutés qu'à la **création**
> du volume. Après l'ajout d'une migration sur une base existante, il faut l'appliquer
> à la main ou repartir d'un volume neuf (`docker compose down -v`).

## Le cycle d'une tâche

```
Issue (US-xx) → branche feat/… → commits → PR liée à l'issue
   → CI verte → revue croisée → squash merge → déploiement → issue fermée
```

Toute tâche existe sous forme d'issue portant son identifiant de user story et ses
critères d'acceptation. **Aucune tâche « dans la tête de quelqu'un ».**

Les issues tracent les **user stories** (`US-01`…), pas les tâches de sprint
(`S1-06`…) : on ne crée pas d'issue pour une tâche purement technique. Dans une PR, on
écrit `Contribue à #N` ; on ne met `Ferme #N` que si la story a été **recettée par le
QA du sprint**, pas simplement codée. Le rôle de QA tourne, il est indiqué dans
`docs/SPRINT_PLAN.md`.

## Branches et commits

| Règle | Détail |
| :--- | :--- |
| Branche de référence | `main`, protégée, toujours déployable |
| Branches de travail | `feat/`, `fix/`, `docs/`, `chore/`, `test/`, `refactor/` |
| Durée de vie | Moins de 3 jours — au-delà, la tâche était trop grosse, on la redécoupe |
| Commits | Conventional Commits, en français : `feat(collector): ajoute l'enrichissement ASN` |
| Corps du commit | Explique **pourquoi**, pas quoi — le diff dit déjà quoi |
| Taille de PR | Moins de 400 lignes. Une PR trop grosse n'est pas relue, elle est approuvée par lassitude |
| Fusion | Squash merge uniquement |

**Les commits ne portent que le nom de leur auteur humain.** Aucune ligne
d'attribution ajoutée automatiquement par un outil : pas de `Co-Authored-By`
supplémentaire, pas de lien de session, pas de mention « generated with ». La règle
vaut aussi pour les messages de *squash*, que GitHub reconstruit à partir des commits
et où ces lignes peuvent réapparaître : relire le message avant de confirmer une
fusion.

## Les invariants — à ne jamais casser sans ADR

1. **Aucun événement n'est perdu.** Un événement malformé est tracé dans
   `event_rejected`, pas jeté. Une charge utile trop grosse est tronquée à 4 Ko, pas
   rejetée. Un leurre qui n'arrive pas à émettre réessaie.
2. **Le score est explicable.** `somme des contributions de règles == threat_score`.
   Toujours. Une règle déclenchée s'écrit dans `rule_match` avec sa contribution, et le
   verdict se reconstruit depuis la base.
3. **Pas d'apprentissage automatique, pas de LLM dans la détection** (ADR 003). Le
   moteur est un arbre de règles pondérées chargé depuis `rules/detection_rules.yaml`.
   Dans la documentation, on écrit « agent défenseur » et « agent de veille », jamais
   « agent IA ».
4. **Aucune sortie réseau depuis la zone des leurres.** `decoy_net` est déclaré
   `internal` dans le compose : c'est une garantie structurelle, pas une règle de
   pare-feu qu'on peut oublier d'appliquer.
5. **Un leurre n'interprète jamais ce qu'il reçoit.** Pas d'`eval`, pas d'`exec`, pas
   de `subprocess`, aucune écriture disque depuis le chemin d'un leurre.
6. **On écrit en base avant d'enrichir** (ADR 007). Rien qui dépende du réseau n'est
   sur le chemin d'ingestion. Un événement non enrichi est marqué `partial` et repris
   plus tard ; un événement retardé est un événement perdu.
7. **Les mots de passe testés sont stockés en clair.** Ce ne sont pas des identifiants
   légitimes mais ceux que les attaquants essaient : leur contenu *est* la donnée
   analytique. Ils sont exclus de tout export public non pseudonymisé.

## Conventions de code

- Python **3.12+**. Commentaires, docstrings et documentation **en français**.
- Les docstrings expliquent les **choix** et leurs conséquences, pas la syntaxe. Ce
  dépôt sera défendu à l'oral : chaque décision inhabituelle porte sa justification à
  côté d'elle.
- `ruff` (`E,F,I,B,UP,S`) et `black` en ligne de 100. `mypy` non bloquant jusqu'au
  sprint 2. `bandit -ll` doit passer — une alerte qu'on choisit d'ignorer se neutralise
  avec `# nosec <code>` **et** un commentaire qui dit pourquoi. `# noqa` ne concerne
  que ruff : ce sont deux outils distincts, et l'un ne fait pas taire l'autre.
- Aucun secret dans le code ni dans les tests. Les adresses IP des tests viennent des
  plages de documentation RFC 5737 : `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`.
- Toute entrée vient potentiellement d'un attaquant : elle est validée par Pydantic,
  bornée, et jamais interprétée.
- Un test nomme l'exigence qu'il défend et échoue si on retire le correctif. Les tests
  ne servent pas à faire monter un pourcentage.

## Architecture — où vit quoi

| Chemin | Rôle |
| :--- | :--- |
| `src/shield/common/schema.py` | **Le contrat d'événement.** Seul point de couplage entre le back et le front. Toute modification impose de régénérer les types TypeScript (`make types`), et la CI échoue si les deux divergent. |
| `src/shield/decoys/` | Les trois leurres. Écoutent, observent, émettent. N'interprètent rien. |
| `src/shield/collector/api/app.py` | L'API FastAPI. Routes et schémas de réponse — à ne pas changer sans prévenir le front. |
| `src/shield/collector/repositories/` | Tout l'accès aux données. Un protocole, deux implémentations (`memory`, `postgres`), choisies par `SHIELD_STORAGE`. Aucune requête SQL ailleurs dans le code. |
| `src/shield/collector/defender/` | Le moteur de règles, le calcul de score, le profilage. Déterministe, sans effet de bord. |
| `src/shield/collector/models/` | Les modèles SQLAlchemy, mappés sur le SQL — ils ne créent aucune table. |
| `deploy/initdb/` | Le schéma et les migrations, appliqués dans l'ordre alphabétique. **Autorité sur la structure de la base.** |
| `rules/detection_rules.yaml` | Les règles de détection. Autorité sur leur contenu ; la table `detection_rule` en est la projection. |
| `dashboard/` | Le tableau de bord React + Vite + TypeScript. |
| `docs/adr/` | Les décisions structurantes. |
| `docs/SPRINT_PLAN.md` | Le découpage en sprints, les tâches, les points, les rôles. |

### Deux pièges à connaître

**Deux sources de vérité pour la base.** Le SQL de `deploy/initdb/` et les modèles
SQLAlchemy décrivent la même structure. C'est délibéré — le partitionnement déclaratif
s'exprime mal à travers un ORM — mais ce n'est défendable que parce qu'un test
d'intégration compare les deux. Une colonne ajoutée en SQL s'ajoute au modèle dans le
même commit.

**Table partitionnée.** `event` est partitionnée par mois sur `occurred_at`. Toute
contrainte unique doit donc inclure `occurred_at` : PostgreSQL ne sait dans quelle
partition chercher que si on lui donne la clé de partition. Ce n'est pas un choix
esthétique, c'est une contrainte du moteur.

## Revue de code

Toujours par l'autre membre. Personne ne fusionne son propre travail.

Grille de relecture :

1. Le code fait-il ce que l'issue demande ?
2. Les critères d'acceptation sont-ils couverts par un test ?
3. Une entrée fournie par un attaquant est-elle validée ?
4. Un secret a-t-il été introduit ?
5. La documentation suit-elle ?

### Revue renforcée

Toute PR touchant `src/shield/decoys/`, le réseau ou les secrets exige une vérification
explicite de l'invariant :

> Aucun `eval`, `exec`, `subprocess`, aucune écriture disque, aucun contenu attaquant
> interprété, et aucune réponse réseau ne révèle la nature du leurre.

Deux tests automatiques le vérifient (`tests/unit/test_decoys.py`), mais la relecture
humaine reste obligatoire : un test ne voit pas ce qu'on ne lui a pas appris à voir.

## Definition of Done

Une tâche est terminée lorsque :

- le code est fusionné dans `main` ;
- les tests associés passent ;
- la documentation est à jour ;
- la fonctionnalité est déployée sur l'environnement de démonstration ;
- **l'autre membre a pu la faire fonctionner de son côté.**

## Décisions structurantes

Toute décision d'architecture fait l'objet d'un ADR dans `docs/adr/`. Cela évite de
rejouer trois fois le même débat — et le jury demandera *pourquoi*, pas seulement *quoi*.

## Blocages

Tout blocage de plus de 4 heures est signalé sur Discord et, si nécessaire, escaladé au
mentor. Interdiction implicite de s'acharner seul une journée entière.

## Instructions pour les outils d'aide au développement

- **Lire ce fichier et `docs/SPRINT_PLAN.md` avant de proposer quoi que ce soit.**
- Ne pas réécrire un module entier pour un correctif de trois lignes.
- Ne pas supprimer un commentaire qui explique un choix : il sert à la soutenance
  autant qu'au code.
- Quand une décision structurante est prise, écrire l'ADR dans le même commit.
- S'arrêter et demander quand une tâche implique de changer un invariant ci-dessus, le
  contrat d'événement, ou une route de l'API.
- En cas de désaccord avec une consigne ponctuelle, c'est ce fichier qui tranche — et
  si ce fichier a tort, le corriger ici plutôt que de le contourner.
