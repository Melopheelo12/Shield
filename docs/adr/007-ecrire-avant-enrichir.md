# ADR 007 — Écrire en base avant d'enrichir

**Statut :** Accepté · **Date :** 2026-09-25 · **Décideurs :** Ryan, Antho

## Contexte

L'objectif SMART F1 exige **zéro perte d'événement** jusqu'à 50 événements par seconde.
L'objectif F2 exige que 95 % des adresses soient enrichies, ce qui implique un appel à
AbuseIPDB — un service tiers, gratuit, limité à 1 000 requêtes par jour, et qui peut
être lent ou indisponible.

La question : l'enrichissement doit-il précéder ou suivre l'écriture en base ?

## Options envisagées

1. **Écrire d'abord, enrichir ensuite**, de façon asynchrone.
2. **Enrichir d'abord, écrire l'événement complet.**

## Décision

**Option 1.** Le collecteur valide, rattache à une session, **écrit en base**, puis
répond `202 Accepted`. L'enrichissement se fait hors du chemin critique.

## Conséquences

### Positives

- La disponibilité d'AbuseIPDB n'a **aucune influence** sur l'objectif « zéro perte ».
- Le leurre n'attend jamais un service tiers pour être libéré.
- La dégradation gracieuse devient naturelle : un événement non enrichi est marqué
  `pending` et complété plus tard.

### Négatives (assumées)

- Un événement peut apparaître brièvement dans le tableau de bord sans pays ni score de
  réputation. L'interface doit donc gérer un état « en cours d'enrichissement ».
- Deux écritures au lieu d'une : un `INSERT` puis un `UPDATE`.

## Justification en une phrase

Un événement non enrichi est une donnée incomplète ; un événement perdu est une donnée
absente. **Le premier se rattrape, le second non.**
