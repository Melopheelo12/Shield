# Architecture Decision Records

Chaque décision structurante fait l'objet d'une fiche courte : contexte, options
envisagées, décision retenue, conséquences, alternatives écartées.

Cela évite de rejouer trois fois le même débat, et constitue une trace précieuse pour
la soutenance — le jury demandera *pourquoi*, pas seulement *quoi*.

| N° | Titre | Statut |
| :---: | :--- | :--- |
| [001](001-choix-du-mvp.md) | Choix du MVP | Accepté |
| [002](002-perimetre-shield.md) | Évolution du périmètre vers SHIELD | **À valider (J3)** |
| [003](003-moteur-de-regles.md) | Moteur de règles plutôt qu'apprentissage automatique | Accepté |
| [004](004-postgresql.md) | PostgreSQL partitionné plutôt que base orientée documents | Accepté |
| [005](005-typescript.md) | TypeScript plutôt que JavaScript | Accepté |
| [006](006-docker-compose.md) | Docker Compose plutôt que Kubernetes | Accepté |
| [007](007-ecrire-avant-enrichir.md) | Écrire en base avant d'enrichir | Accepté |
| [008](008-relais-d-entree-des-leurres.md) | Exposer les leurres par un relais d'entrée et le PROXY protocol | **Proposé** |

## Modèle

```markdown
# ADR NNN — Titre

**Statut :** Proposé | Accepté | Remplacé par ADR-XXX
**Date :** AAAA-MM-JJ · **Décideurs :** Ryan, Antho

## Contexte
## Options envisagées
## Décision
## Conséquences
### Positives
### Négatives (assumées)
## Alternatives écartées
```
