# ADR 008 — Exposer les leurres par un relais d'entrée et le PROXY protocol

**Statut :** Proposé · **Date :** 2026-10-08 · **Décideurs :** Ryan, Antho

## Contexte

La recette du sprint 0 (#52) a montré que **les ports des leurres n'étaient pas
publiés** : Docker ignore la publication de ports pour un conteneur relié uniquement à
des réseaux `internal`. Or `decoy_net` et `ingest_net` le sont, et doivent le rester :
c'est l'invariant 4 de `CONTRIBUTING.md` (« aucune sortie réseau depuis la zone des
leurres, garantie structurelle et non règle de pare-feu »). En l'état, aucun événement
venu d'Internet ne pouvait arriver, et le jalon J4 était impossible.

Deux exigences s'opposent : laisser **entrer** Internet jusqu'aux leurres, sans leur
ouvrir de **sortie**, et conserver **l'adresse réelle** de l'attaquant, donnée
centrale de tout l'enrichissement et du scoring.

## Options envisagées

1. **Réseau `edge` non interne pour les leurres**, et sortie bloquée sur l'hôte par une
   règle `iptables` dans la chaîne `DOCKER-USER`.
2. **Relais TCP** sur un réseau non interne, qui transmet les connexions aux leurres
   restés sur `decoy_net`, et leur passe l'adresse réelle par le **PROXY protocol v1**.

## Décision

**Option 2.** Un conteneur `edge` (nginx, module `stream` seul) publie les ports 22, 80
et 21, et relaie chaque connexion au leurre correspondant en la préfixant d'une ligne
`PROXY TCP4 <ip source> <ip destination> <port source> <port destination>`. Le leurre
(`DECOY_PROXY_PROTOCOL=1`) lit cette ligne avant tout dialogue et l'utilise comme
adresse de l'attaquant ; une connexion sans en-tête valide est fermée sans événement.

## Conséquences

### Positives

- **L'invariant 4 est intact** : les leurres ne sont reliés qu'à des réseaux internes,
  ce que vérifie un test sur `docker-compose.yml`. Un oubli de pare-feu sur le VPS
  n'ouvre aucune sortie.
- L'adresse et le port source réels arrivent au collecteur sans changement du contrat
  d'événement.
- Le même comportement en local et sur le VPS : rien ne dépend de la configuration de
  l'hôte.

### Négatives (assumées)

- **Un conteneur exposé de plus.** `edge` a une route sortante (`edge_net`). Il ne fait
  que relayer des octets vers trois destinations fixes, sans module `http` ni contenu
  interprété ; il tourne en non-root, en lecture seule, sans capacités.
- **La confiance dans l'en-tête repose sur la topologie** : seul `edge` peut joindre
  les leurres sur `decoy_net`, donc seul lui peut écrire l'en-tête. Un leurre ne doit
  jamais être publié directement avec `DECOY_PROXY_PROTOCOL=1`.
- Sur Docker Desktop (macOS, Windows), l'adresse vue par `edge` est celle de la machine
  virtuelle : l'adresse réelle n'est garantie que sur un hôte Linux.

## Alternatives écartées

- **Option 1** : plus simple et sans conteneur supplémentaire, mais l'isolation des
  leurres dépendrait d'une règle de pare-feu qu'un redémarrage, une réinstallation ou
  un oubli peut faire disparaître — exactement ce que l'invariant 4 interdit. Elle ne
  protège pas non plus un poste de développement.
- **Relais sans PROXY protocol** : tous les événements porteraient l'adresse du relais,
  ce qui viderait de sens l'enrichissement, les compteurs par adresse et les sessions.
