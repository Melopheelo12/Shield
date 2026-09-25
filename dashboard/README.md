# Tableau de bord SHIELD

React 18 + TypeScript + Vite.

```bash
npm install
npm run dev        # http://localhost:5173, proxy vers le collecteur sur :8000
npm run typecheck
npm run build
```

## Le contrat d'événement

`src/types/events.ts` est **généré** depuis les modèles Pydantic du back-end.
Ne le modifiez pas à la main : lancez `make types` à la racine du dépôt.

La CI vérifie que le fichier versionné est à jour. Si Ryan renomme un champ sans
régénérer, la compilation du front échoue — c'est exactement le but.

## Développer sans back-end

Le générateur d'événements factices permet de travailler sans qu'aucun leurre ne
tourne :

```bash
# terminal 1, à la racine du dépôt
make run-api
# terminal 2
make fake
# terminal 3
cd dashboard && npm run dev
```
