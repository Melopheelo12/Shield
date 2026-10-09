# Tableau de bord SHIELD

React 18 + TypeScript + Vite. Thème sombre par défaut, aucune ressource externe
(la CSP de nginx n'autorise que `'self'`).

## Démarrer et tester

À la racine du dépôt, une seule commande :

```bash
make dev        # collecteur en mémoire + attaques factices + tableau de bord
```

Le navigateur s'ouvre sur <http://localhost:5173>. `RATE=10 make dev` accélère
les attaques simulées ; Ctrl+C arrête tout. Aucun leurre n'est exposé.

## Les pages

| Route | Rôle |
| --- | --- |
| `#/` | Vue d'ensemble : chiffres clés, chronologie, flux en direct, classements |
| `#/carte` | Carte des menaces : pays d'origine, adresses par pays, lien vers le journal filtré |
| `#/journal` | Journal paginé et filtrable ; un clic ouvre le détail et le verdict expliqué |
| `#/defense` | Liste de blocage (ufw, iptables, nginx), règles actives, arrêt d'urgence |
| `#/sandbox` | Déroulé d'une partie d'entraînement et grille de détection |

La carte reste vide tant que la géolocalisation (US-07) n'est pas active côté
collecteur : la page l'indique au lieu d'afficher une carte trompeuse.

## Vérifier

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

La CI rejoue ces quatre étapes (job « Tableau de bord »).

## Le contrat d'événement

`src/types/events.ts` est **généré** depuis les modèles Pydantic du back-end.
Ne le modifiez pas à la main : lancez `make types` à la racine du dépôt.

La CI vérifie que le fichier versionné est à jour. Si un champ est renommé sans
régénérer, la compilation du front échoue — c'est exactement le but.
