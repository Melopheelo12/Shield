# ADR 005 — TypeScript plutôt que JavaScript pour le tableau de bord

**Statut :** Accepté · **Date :** 2026-09-25 · **Décideurs :** Ryan, Antho

## Contexte

L'étape 1 avait retenu « React 18 + Vite » sans trancher entre TypeScript et JavaScript.

Le projet est développé par deux personnes sur deux lanes séparées : Ryan au back-end,
Antho au front-end. Le **contrat d'événement** (`src/shield/common/schema.py`) est leur
unique point de couplage.

## Options envisagées

1. **TypeScript**, avec des types générés depuis les modèles Pydantic.
2. **JavaScript**, avec validation à l'exécution (Zod).
3. **JavaScript** sans validation.

## Décision

**Option 1.** Le tableau de bord est écrit en TypeScript. `shield.tools.gen_ts_types`
génère `dashboard/src/types/events.ts` depuis les modèles Pydantic, et la CI échoue si
le fichier versionné est périmé.

## Conséquences

### Positives

- Une rupture de contrat est détectée **à la compilation**, immédiatement. Si Ryan
  renomme un champ sans régénérer, la CI échoue avant que le front ne casse en démo.
- Auto-complétion sur les données de l'API : moins d'erreurs de frappe sur des noms de
  champs, qui sont l'erreur la plus fréquente et la plus stupide.
- C'est le filet de sécurité le plus rentable pour deux lanes qui avancent en parallèle.

### Négatives (assumées)

- Quelques heures d'apprentissage pour Antho s'il ne connaît que JavaScript.
- Une étape de génération supplémentaire dans la chaîne de build.

## Alternatives écartées

- **Validation à l'exécution (Zod)** — détecte le problème, mais tard, et seulement sur
  les chemins effectivement parcourus pendant les tests.
- **JavaScript sans validation** — les ruptures de contrat se découvrent en production.
  Pour un projet évalué sur une démonstration en direct, c'est un risque inacceptable.
