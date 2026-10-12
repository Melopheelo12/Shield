# ADR 009 — Authentification : un compte unique défini dans l'environnement

**Statut :** Proposé · **Date :** 2026-10-12 · **Décideurs :** Ryan, Antho

## Contexte

US-19 exige que le tableau de bord soit protégé et qu'une attaque par force brute sur
la connexion soit ralentie après 5 échecs. SHIELD n'a qu'un utilisateur : l'exploitant
de l'instance. Le schéma prévoyait des tables `app_user` et `api_token`, et
`pyproject.toml` la bibliothèque `passlib[bcrypt]`.

Deux constats au moment d'implémenter (S3-01) :

- `passlib` n'est plus maintenue, et elle est **incompatible avec bcrypt 5** (son test
  interne de détection de bogue envoie un mot de passe de plus de 72 octets, que
  bcrypt 5 refuse désormais) ;
- un compte stocké en base doit être créé quelque part (commande d'initialisation,
  premier lancement…), ce qui ajoute une étape au déploiement « en moins de dix minutes ».

## Options envisagées

1. **Compte en base** (`app_user`), mot de passe haché en bcrypt, commande de création.
2. **Compte dans l'environnement** (`ADMIN_USERNAME` / `ADMIN_PASSWORD` du `.env`),
   comparé à temps constant, JWT HS256 à courte durée de vie.

## Décision

**Option 2.** Le mot de passe vit déjà dans un fichier `.env` qui contient les autres
secrets (`POSTGRES_PASSWORD`, `JWT_SECRET`, `INGEST_TOKEN`) et dont la protection
conditionne déjà toute la sécurité de l'instance. Le hacher en base n'ajouterait pas de
protection contre l'attaquant qui lit ce fichier.

- Comparaison à temps constant des empreintes SHA-256 de l'identifiant et du mot de
  passe ; sans `ADMIN_PASSWORD` configuré, **personne n'entre**.
- Après 5 échecs en 15 min depuis une adresse : 429 avec `Retry-After`, délai doublé à
  chaque échec (30 s → 15 min). Le mot de passe n'est même pas comparé pendant le délai.
  nginx limite en plus `/auth/login` à 5 requêtes par minute.
- En production (`SHIELD_ENV=prod`), le collecteur **refuse de démarrer** avec un secret
  d'exemple (`change-me…`) ou un `JWT_SECRET` de moins de 32 caractères.
- WebSocket : le jeton passe en paramètre `token`, faute d'en-tête possible côté navigateur.
- Liste de blocage : un pare-feu ne se connecte pas ; il présente `BLOCKLIST_TOKEN`.

## Conséquences

### Positives

- Zéro étape de plus au déploiement, zéro dépendance cassée.
- Changer le mot de passe = modifier `.env` et redémarrer, comme tout autre secret.

### Négatives (assumées)

- Le compteur d'échecs est en mémoire : un redémarrage le remet à zéro.
- Le jeton du WebSocket peut apparaître dans les journaux d'accès de nginx ; sa durée
  de vie courte (30 min) limite l'exposition.
- `app_user` et `api_token` deviennent inutilisés : à retirer, ou à garder pour une v2
  multi-comptes. `passlib` est retiré des dépendances.
- Bibliothèque JWT : **PyJWT**, et non `python-jose`, qui porte une vulnérabilité sans
  correctif (CVE-2026-85394, confusion de clés HMAC — non exploitable ici puisque seul
  HS256 est accepté, mais une brique d'authentification ne garde pas de dette connue).

## Alternatives écartées

- **Option 1** : pertinente avec plusieurs comptes ou des rôles, ce qui est hors
  périmètre v1 (ADR 002).
- **Session par cookie** : impose une protection CSRF, inutile avec un jeton porteur.
