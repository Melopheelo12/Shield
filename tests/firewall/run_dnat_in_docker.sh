#!/usr/bin/env bash
# Teste scripts/apply_blocklist.sh derrière un DNAT, comme sur l'hôte avec Docker (#99).
#
#   client hostile 198.51.100.7 ─┐
#   client neutre  198.51.100.8 ─┴─ routeur 198.51.100.2 | 203.0.113.2 ── serveur 203.0.113.20
#                                   (DNAT 22 → 2222, 8443 → 8443, chaîne forward, pare-feu)
#
# Le routeur joue le rôle de l'hôte : le port 22 y est traduit vers 2222, comme le relais
# des leurres publie 22:2222. Critère de #99 : une adresse de la liste de blocage atteint
# toujours le leurre (22 → 2222) mais plus le port protégé, même si 2222 figure dans
# PROTECTED_PORTS (port interne de conteneur, à ignorer).
#
#   ./tests/firewall/run_dnat_in_docker.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
ID="shield-fw-$$"
cleanup() {
  docker rm -f "$ID-router" "$ID-server" "$ID-hostile" "$ID-neutral" >/dev/null 2>&1 || true
  docker network rm "$ID-a" "$ID-b" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --subnet 198.51.100.0/24 "$ID-a" >/dev/null
docker network create --subnet 203.0.113.0/24 "$ID-b" >/dev/null

run() { docker run -d --name "$1" "${@:2}" alpine:3.20 sleep 600 >/dev/null; }
run "$ID-router" --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  --network "$ID-a" --ip 198.51.100.2 -v "${SCRIPTS_DIR:-$PWD/scripts}:/scripts:ro"
docker network connect --ip 203.0.113.2 "$ID-b" "$ID-router"
run "$ID-server" --network "$ID-b" --ip 203.0.113.20
run "$ID-hostile" --network "$ID-a" --ip 198.51.100.7
run "$ID-neutral" --network "$ID-a" --ip 198.51.100.8

ex() { docker exec "$@"; }
ex "$ID-router" apk add -q --no-progress bash curl nftables python3 >/dev/null
ex "$ID-server" apk add -q --no-progress python3 >/dev/null
for c in hostile neutral; do ex "$ID-$c" apk add -q --no-progress curl >/dev/null; done

# Serveur : un « leurre » sur 2222 et un « tableau de bord » sur 8443.
ex -d "$ID-server" python3 -m http.server 2222
ex -d "$ID-server" python3 -m http.server 8443

# Routeur : DNAT façon Docker, puis la liste de blocage servie localement. Le masquerade
# en sortie n'existe que pour le banc de test (Docker rejette sur ses ponts une source
# étrangère au réseau) ; il agit en postrouting, APRÈS la chaîne forward du pare-feu,
# qui voit donc toujours l'adresse réelle du client.
ex -i "$ID-router" nft -f - <<'NFT'
table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    tcp dport 22 dnat to 203.0.113.20:2222
    tcp dport 8443 dnat to 203.0.113.20:8443
  }
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "eth1" masquerade
  }
}
NFT
ex "$ID-router" sh -c 'mkdir -p /srv/api/v1 && printf "198.51.100.7\n::::::\n" > /srv/api/v1/blocklist'
ex -d "$ID-router" sh -c 'cd /srv && python3 -m http.server 9000 --bind 127.0.0.1'
sleep 2

probe() { ex "$1" curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://198.51.100.2:$2/" || true; }
fail() { echo "ÉCHEC : $*"; exit 1; }

echo "== sans pare-feu : tout le monde passe"
[ "$(probe "$ID-hostile" 22)" = 200 ] || fail "montage : le leurre n'est pas joignable"
[ "$(probe "$ID-hostile" 8443)" = 200 ] || fail "montage : le port protégé n'est pas joignable"

echo "== pare-feu appliqué (PROTECTED_PORTS=\"8443 2222\", la configuration fautive de #99)"
ex -e SHIELD_BLOCKLIST_CONFIG=/nonexistent -e SHIELD_URL=http://127.0.0.1:9000 \
   -e BLOCKLIST_TOKEN=t -e PROTECTED_PORTS="8443 2222" -e ALLOWLIST=192.0.2.10 \
   -e DRY_RUN=0 "$ID-router" bash /scripts/apply_blocklist.sh

echo "== l'adresse hostile atteint toujours le leurre (22 → 2222)…"
[ "$(probe "$ID-hostile" 22)" = 200 ] || fail "#99 : l'attaquant est coupé du leurre"
echo "== … mais plus le port protégé"
[ "$(probe "$ID-hostile" 8443)" = 000 ] || fail "le port protégé reste joignable"
echo "== l'adresse neutre atteint les deux"
[ "$(probe "$ID-neutral" 22)" = 200 ] || fail "neutre coupée du leurre"
[ "$(probe "$ID-neutral" 8443)" = 200 ] || fail "neutre coupée du port protégé"
echo "== « :::::: » rejetée sans casser la mise à jour (2 lignes reçues, 1 bloquée)"
ex "$ID-router" nft list set inet shield_defense hostile6 | grep -q "elements" \
  && fail "une adresse IPv6 invalide est passée"

echo "TOUT EST OK"
