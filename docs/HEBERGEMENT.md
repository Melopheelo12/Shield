# Hébergement — conditions d'utilisation et durcissement (S0-09, S0-10)

> Relevé du 4 octobre 2026. Les conditions des hébergeurs changent : **relire la
> clause citée le jour de l'achat** et conserver une copie PDF datée dans le drive
> de l'équipe.

## 1. Ce que nous devons pouvoir faire

SHIELD expose **volontairement** trois services (22, 80, 21) et attire du **trafic
entrant hostile**. Il ne scanne personne, n'attaque personne et n'a **aucune route
sortante** depuis la zone leurre. Ce que nous cherchons dans chaque AUP :

1. une interdiction explicite des honeypots ou de la « recherche en sécurité » ;
2. une clause sur la réputation de l'IP ou sur les « usages nuisibles au réseau » qui
   pourrait être invoquée contre un serveur qui reçoit beaucoup d'attaques ;
3. ce qui nous est interdit **en sortie** (scan, IP usurpée), pour ne jamais le faire.

## 2. Relevé

| Hébergeur | Clause pertinente | Verdict |
| --- | --- | --- |
| **Hetzner Cloud** | Interdits : minage, « *the scanning of foreign networks or foreign IP addresses* », « *the use of fake source IPs* ». Rien sur les honeypots ni le trafic entrant. | ✅ **Retenu.** Notre seule contrainte est de ne jamais scanner en retour : l'enrichissement reste passif (GeoIP local, API de réputation). |
| **OVHcloud VPS** | Pas d'interdiction des honeypots. Mais : « *the Client agrees to not use the VPS Service in a way that is detrimental to other OVHcloud clients or that harms the reputation of the Host Server's IP address* », et OVHcloud « *reserves the right to interrupt the VPS connection to the Internet* » s'il détecte un problème de sécurité. | 🟡 **Repli.** Autorisé sur le papier, mais leur détection automatique peut prendre nos leurres pour une machine compromise et couper le réseau. |
| **DigitalOcean** | « *You may not […] conduct any security or malware research on or using the Services, without DigitalOcean's prior written consent.* » | ❌ **Exclu** sans accord écrit préalable. Un honeypot est de la recherche en sécurité. |
| **Scaleway** | Conditions spécifiques Instances en PDF, non relues dans ce relevé. | ⏳ À lire si Hetzner et OVHcloud tombent. |

Sources : [Hetzner — Cloud Server policy](https://www.hetzner.com/legal/cloud-server/),
[Hetzner — System policies](https://www.hetzner.com/legal/system-policies/),
[OVHcloud — Conditions particulières VPS v4.1](https://storage.gra.cloud.ovh.net/v1/AUTH_325716a587c64897acbef9a4a4726e38/contracts/7824b7f-Conditions_Particulieres_VPS-WE-4.1.pdf),
[DigitalOcean — Acceptable Use Policy](https://www.digitalocean.com/legal/acceptable-use-policy),
[Scaleway — Contrats](https://www.scaleway.com/en/contracts/).

## 3. Décision proposée

- **Hébergeur principal : Hetzner Cloud** (le plus petit CX suffit : 2 vCPU, 4 Go).
- **Repli : OVHcloud VPS**, en prévenant leur support *avant* la mise en ligne.
- **Avant de payer**, écrire au support de l'hébergeur retenu. Une ligne suffit :
  « serveur de recherche académique exposant des services leurres en faible
  interaction, sans aucun trafic sortant initié ». Archiver la réponse : c'est
  notre preuve en cas de signalement d'abus.

## 4. Durcissement (S0-10, US-49)

Une fois le VPS livré, en root, une seule fois (Ubuntu 24.04 LTS) :

```bash
ADMIN_USER=antho \
ADMIN_SSH_PORT=49222 \
ADMIN_PUBKEY="ssh-ed25519 AAAA… antho@portable" \
./scripts/harden_vps.sh
```

Le script :

| Exigence | Ce qui est fait |
| --- | --- |
| SSH d'admin sur clé, port décalé, mot de passe désactivé | `sshd` sur `ADMIN_SSH_PORT`, `PasswordAuthentication no`, `PermitRootLogin no`, `AllowUsers`, configuration validée par `sshd -t` avant tout redémarrage. Le port 22 est libéré pour le leurre. |
| Pare-feu : 22, 80, 21 et le port d'admin | `ufw` refuse tout le reste en entrée. **Docker contourne `ufw`** pour les ports publiés : une chaîne `DOCKER-USER` bloque aussi tout port de conteneur autre que 22/80/21 (le 8443 de nginx n'est donc joignable que par tunnel SSH). |
| Mises à jour de sécurité automatiques | `unattended-upgrades` limité à la source `-security`, redémarrage auto à 04:30 si nécessaire (les conteneurs repartent : `restart: unless-stopped`). |
| Aucun secret sur la machine | Aucune clé privée créée ; `AllowAgentForwarding no` (personne ne peut réutiliser l'agent SSH d'un admin connecté) ; le script **échoue** s'il trouve une clé privée dans `/root` ou `/home`. Le `.env` est créé en `600`. |

Accès au tableau de bord, uniquement par tunnel :

```bash
ssh -p 49222 -L 8443:localhost:8443 antho@<ip-du-vps>
# puis https://localhost:8443
```

## 5. Mise en ligne et jalon J4

```bash
git clone https://github.com/Melopheelo12/Shield.git && cd Shield
cp .env.example .env && chmod 600 .env   # puis générer de vrais secrets
docker compose up -d
docker compose ps
# premier événement réel (peut prendre de quelques minutes à une heure) :
docker compose exec collector python -c \
  "import urllib.request;print(urllib.request.urlopen('http://localhost:8000/api/v1/stats/overview').read().decode())"
```

**J4 est atteint** quand `events` > 0 avec une IP source qui n'est pas la nôtre.

> ⚠️ **Bloquant constaté en recette** : tant que les leurres ne sont reliés qu'à des
> réseaux `internal`, Docker ne publie pas leurs ports. Aucun événement d'Internet
> ne peut arriver. Voir l'issue correspondante avant le `docker compose up`.
