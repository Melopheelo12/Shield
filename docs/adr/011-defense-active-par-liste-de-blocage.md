# ADR 011 — Défense active : la liste de blocage protège les services réels

**Statut :** Proposé · **Date :** 2026-10-12 · **Décideurs :** Ryan, Antho

## Contexte

L'agent défenseur qualifie les attaques et produit une liste de blocage (US-43), mais
rien ne l'applique : il faut la recopier à la main dans un pare-feu. Le périmètre exclut
« toute riposte active » (ADR 002) : il s'agit d'attaquer en retour, ce qui reste exclu.
Bloquer chez soi n'est pas riposter.

Contresens à éviter : bloquer les attaquants **sur les leurres** viderait le honeypot de
sa raison d'être.

## Options envisagées

1. Rien d'automatique : la liste reste un export à appliquer à la main.
2. **Script nftables opt-in**, lancé par un minuteur systemd, qui ferme aux adresses
   hostiles les ports des **services réels** de la machine (tableau de bord, vrai SSH).
3. fail2ban, avec un filtre sur les journaux du collecteur.

## Décision

**Option 2**, désactivée par défaut (`DRY_RUN=1`) :

- table nftables dédiée (`inet shield_defense`), remplacée atomiquement, supprimable
  d'une commande ;
- liste blanche **obligatoire** et évaluée en premier ; refus de démarrer sans elle ;
- refus de protéger un port de leurre ;
- adresses privées, de bouclage et locales jamais bloquées ; chaque ligne reçue validée ;
- liste injoignable : les règles en place restent (code 2, pas une erreur).

## Conséquences

### Positives

- Le renseignement du honeypot protège la machine qui l'héberge ; le même script peut
  tourner sur d'autres serveurs de l'utilisateur.
- Testé dans un espace réseau isolé, trafic réel compris (`tests/firewall/`).

### Négatives (assumées)

- Un faux positif ferme le tableau de bord ou le vrai SSH à une adresse légitime pendant
  `DAYS` jours : d'où la liste blanche obligatoire et le seuil `MIN_SCORE=60`.
- Ne protège que les ports listés ; ce n'est pas un pare-feu complet.

## Alternatives écartées

- **Option 1** : la liste n'est utile que si elle est appliquée, et à la main elle ne
  l'est pas.
- **Option 3** : fail2ban réagit aux journaux d'un service ; ici l'information est déjà
  qualifiée par l'agent, l'API suffit.
