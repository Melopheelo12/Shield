# ADR 003 — Moteur de règles plutôt qu'apprentissage automatique

**Statut :** Accepté · **Date :** 2026-09-25 · **Décideurs :** Ryan, Antho

## Contexte

L'agent défenseur doit attribuer un niveau de menace à une session d'attaque. Deux
familles d'approches existent : un moteur de règles écrites à l'avance, ou un modèle
statistique entraîné sur les données collectées.

La user story US-13 exige que l'opérateur puisse voir **quelles règles** ont produit un
score — « ne jamais avoir à faire confiance à une boîte noire ». US-17 exige que chaque
règle soit expliquée en langage clair, à destination d'un utilisateur non expert.

## Options envisagées

1. **Moteur de règles pondérées, déterministe.**
2. **Détection d'anomalies non supervisée** (scikit-learn, isolation forest).
3. **Appel à un LLM** pour qualifier chaque session suspecte.

## Décision

**Option 1.** L'agent défenseur est un moteur de règles déclaratives, chargées depuis
`rules/detection_rules.yaml`, dont le score est une somme de poids plafonnée à 100.

## Conséquences

### Positives

- **Explicable.** Chaque point du score est attribué à une règle nommée et décrite. La
  somme des contributions est exactement égale au score affiché, et un test unitaire
  protège cet invariant.
- **Fonctionnel dès le premier événement.** Aucun historique n'est nécessaire.
- **Déterministe, donc testable.** Le rejeu d'un jeu d'événements figé produit toujours
  le même verdict — vérifié en CI.
- **Modifiable sans redéployer.** Les règles vivent dans un fichier YAML, rechargé à chaud.
- **Défendable en soutenance.** Le jury peut vérifier un score ligne à ligne, en direct.
- **Pédagogique.** Le persona étudiant apprend ce qui est détecté et pourquoi.

### Négatives (assumées)

- **L'agent ne détecte que ce pour quoi une règle existe.** Une technique d'attaque
  inédite passe inaperçue. C'est le prix de l'explicabilité.
- **La qualité du produit dépend directement de la qualité des règles.** C'est
  précisément pourquoi la sandbox n'est pas un gadget : elle mesure objectivement ce que
  les règles détectent et ce qu'elles manquent.

## Alternatives écartées

- **Apprentissage automatique** — écarté dès l'étape 1 pour la même raison : aucun
  historique au démarrage, et un modèle non supervisé sur un jeu de données naissant
  produit surtout des faux positifs, que nous n'aurions aucun moyen de qualifier.
  S'ajoute le problème rédhibitoire de l'explicabilité. Reporté en v2, une fois
  plusieurs mois de données réelles accumulées.
- **LLM** — coût, latence, dépendance réseau dans le chemin critique, et surtout
  non-déterminisme : deux exécutions sur la même session peuvent diverger, ce qui rend
  le verdict intestable et indéfendable.
