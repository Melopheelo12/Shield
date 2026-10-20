# ADR 010 — Alertes : fenêtres glissantes en mémoire et machine à états par seuil

**Statut :** Proposé · **Date :** 2026-10-12 · **Décideurs :** Ryan, Antho

## Contexte

US-30 exige une alerte **exactement une fois par franchissement** de seuil, contenant
la règle, la valeur observée et un lien vers la vue filtrée. US-31 rend le seuil, la
fenêtre et la période de silence configurables depuis l'interface. L'alerte ne doit
jamais retarder ni faire perdre un événement (objectif F1).

## Options envisagées

1. **Requête périodique en base** (toutes les 15 s, compter les événements de la fenêtre).
2. **Fenêtres glissantes en mémoire**, alimentées à l'ingestion, et une machine à états
   par seuil.

## Décision

**Option 2.** Chaque seuil est *armé* ; un franchissement produit une alerte et le
*désarme* ; il ne se **réarme** que lorsque la mesure repasse sous le seuil. Une
**période de silence** empêche en plus une activité qui oscille autour du seuil de
produire une alerte à chaque oscillation.

L'ingestion ne fait qu'ajouter une observation et déposer l'alerte dans une file ; une
tâche de fond l'envoie (Discord, courriel), chaque canal isolé des pannes des autres, et
trace chaque franchissement dans `alert` avec le résultat par canal. Les seuils sont
enregistrés dans `alert_threshold` (`004_alerting.sql`).

## Conséquences

### Positives

- Alerte immédiate, sans aucune requête en base sur le chemin d'ingestion.
- Logique pure et à horloge injectée : le test d'unicité (S4-03) rejoue cinquante
  événements au-dessus du seuil et vérifie qu'une seule alerte part.

### Négatives (assumées)

- **Un redémarrage vide les fenêtres et réarme les seuils** : une activité déjà
  au-dessus du seuil peut produire une seconde alerte juste après un redémarrage.
- Les mesures ne valent que pour un seul processus collecteur — c'est le cas (ADR 006).

## Alternatives écartées

- **Option 1** : survit aux redémarrages, mais ajoute une requête d'agrégation
  périodique par seuil et une latence d'alerte égale à la période d'interrogation.
- **Une alerte à chaque événement au-dessus du seuil** : c'est précisément ce que US-30
  interdit, et ce qui fait désactiver les alertes au bout d'une journée.
