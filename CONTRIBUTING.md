# Contribuer à SHIELD

## Mise en route

```bash
make install     # venv + dépendances + crochets de pre-commit
cp .env.example .env
make check       # tout ce que la CI vérifie
```

## Le cycle d'une tâche

```
Issue (US-xx) → branche feat/… → commits → PR liée à l'issue
   → CI verte → revue croisée → squash merge → déploiement → issue fermée
```

Toute tâche existe sous forme d'issue portant son identifiant de user story et ses
critères d'acceptation. **Aucune tâche « dans la tête de quelqu'un ».**

## Branches et commits

| Règle | Détail |
| :--- | :--- |
| Branche de référence | `main`, protégée, toujours déployable |
| Branches de travail | `feat/`, `fix/`, `docs/`, `chore/`, `test/`, `refactor/` |
| Durée de vie | Moins de 3 jours — au-delà, la tâche était trop grosse, on la redécoupe |
| Commits | Conventional Commits : `feat(collector): add ASN enrichment` |
| Taille de PR | Moins de 400 lignes. Une PR trop grosse n'est pas relue, elle est approuvée par lassitude |
| Fusion | Squash merge uniquement |

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
