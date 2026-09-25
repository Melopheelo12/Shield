## Ce que fait cette PR

<!-- Une ou deux phrases. Le "pourquoi" compte plus que le "comment". -->

Ferme #

## User story couverte

- [ ] US-___ — les critères d'acceptation de l'issue sont tous vérifiés

## Checklist auteur

- [ ] Moins de 400 lignes modifiées (sinon : pourquoi ?)
- [ ] Commits au format Conventional Commits
- [ ] Tests ajoutés ou mis à jour, et ils échouent sans le correctif
- [ ] Documentation à jour (README, ADR, docstrings)
- [ ] Aucun secret, aucune vraie adresse IP dans le code ou les tests

## Checklist relecteur

- [ ] Le code fait ce que l'issue demande
- [ ] Les critères d'acceptation sont couverts par un test
- [ ] Toute entrée fournie par un attaquant est validée

### Si cette PR touche `src/shield/decoys/`, le réseau ou les secrets

- [ ] **Invariant vérifié** : aucun `eval`, `exec`, `subprocess`, aucune écriture disque,
      aucun contenu attaquant interprété
- [ ] Aucune réponse réseau ne révèle la nature du leurre
