#!/usr/bin/env bash
# Teste scripts/apply_blocklist.sh pour de vrai, dans l'espace réseau isolé d'un
# conteneur (CAP_NET_ADMIN sur ce seul espace, aucun effet sur l'hôte).
#
#   ./tests/firewall/run_in_docker.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

docker run --rm -i --cap-add NET_ADMIN -v "$PWD/scripts:/scripts:ro" alpine:3.20 sh -s <<'EOF'
set -e
apk add -q --no-progress bash curl nftables python3 >/dev/null

mkdir -p /srv/api/v1
cat > /srv/api/v1/blocklist <<'LIST'
198.51.100.7
203.0.113.9
10.1.2.3
192.168.1.20
172.20.0.5
100.70.0.1
127.0.0.1
300.1.1.1
1.2.3.4; rm -rf /
2001:db8::5
fe80::1
not-an-ip
203.0.113.10
LIST
cd /srv && python3 -m http.server 9000 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1

export SHIELD_BLOCKLIST_CONFIG=/nonexistent SHIELD_URL=http://127.0.0.1:9000 \
       BLOCKLIST_TOKEN=t PROTECTED_PORTS="8443 2222" ALLOWLIST="203.0.113.10 10.0.0.0/8"
fail() { echo "ÉCHEC : $*"; exit 1; }

echo "== refus sans liste blanche"
ALLOWLIST= bash /scripts/apply_blocklist.sh 2>&1 | grep -q "ALLOWLIST vide" || fail "liste blanche"
echo "== refus de bloquer un port de leurre"
PROTECTED_PORTS="22 8443" bash /scripts/apply_blocklist.sh 2>&1 | grep -q "port de leurre" || fail "port leurre"

echo "== essai (DRY_RUN=1) : rien n'est appliqué"
DRY_RUN=1 bash /scripts/apply_blocklist.sh >/dev/null
nft list tables | grep -q shield_defense && fail "le mode essai a appliqué des règles"

echo "== application"
DRY_RUN=0 bash /scripts/apply_blocklist.sh
set4=$(nft list set inet shield_defense hostile4)
set6=$(nft list set inet shield_defense hostile6)
echo "$set4" | grep -q "198.51.100.7" || fail "adresse publique absente"
echo "$set4" | grep -q "203.0.113.9" || fail "adresse publique absente"
for ip in 10.1.2.3 192.168.1.20 172.20.0.5 100.70.0.1 127.0.0.1 300.1.1.1 1.2.3.4; do
  echo "$set4" | grep -q "$ip" && fail "$ip ne devait pas être bloquée"
done
echo "$set6" | grep -q "2001:db8::5" || fail "IPv6 publique absente"
echo "$set6" | grep -q "fe80" && fail "fe80::1 ne devait pas être bloquée"
nft list chain inet shield_defense input | grep -q "tcp dport { 2222, 8443 }" || fail "ports"
nft list set inet shield_defense allow4 | grep -q "10.0.0.0/8" || fail "liste blanche"

echo "== trafic réel : l'adresse hostile est coupée, les autres passent"
ip link add shield0 type dummy && ip link set shield0 up
for a in 198.51.100.7 198.51.100.200 203.0.113.10; do ip addr add "$a/32" dev shield0; done
mkdir -p /www && echo ok > /www/index.html
(cd /www && python3 -m http.server 8443 --bind 198.51.100.200 >/dev/null 2>&1 &)
for _ in 1 2 3 4 5 6 7 8 9 10; do
  netstat -ltn 2>/dev/null | grep -q "198.51.100.200:8443" && break
  sleep 0.5
done
probe() { curl -s -o /dev/null -w "%{http_code}" --max-time 3 --interface "$1" http://198.51.100.200:8443/ || true; }
[ "$(probe 198.51.100.200)" = 200 ] || fail "adresse neutre bloquée"
[ "$(probe 203.0.113.10)" = 200 ] || fail "adresse de la liste blanche bloquée"
[ "$(probe 198.51.100.7)" = 000 ] || fail "adresse hostile NON bloquée"
nft list chain inet shield_defense input | grep -Eq "counter packets [1-9]" || fail "compteur à zéro"

echo "== idempotent : deuxième passage, une seule table"
DRY_RUN=0 bash /scripts/apply_blocklist.sh 2>/dev/null
[ "$(nft list tables | grep -c shield_defense)" = 1 ] || fail "table dupliquée"

echo "== liste injoignable : règles conservées, code 2"
set +e; SHIELD_URL=http://127.0.0.1:1 DRY_RUN=0 bash /scripts/apply_blocklist.sh 2>/dev/null; code=$?; set -e
[ "$code" = 2 ] || fail "code $code au lieu de 2"
nft list set inet shield_defense hostile4 | grep -q "198.51.100.7" || fail "règles perdues"

echo "== liste vide : table valide, ensembles vides"
: > /srv/api/v1/blocklist
DRY_RUN=0 bash /scripts/apply_blocklist.sh 2>/dev/null
nft list set inet shield_defense hostile4 | grep -q "198.51.100.7" && fail "ancienne adresse restée"

echo "TOUT EST OK"
EOF
