#!/usr/bin/env bash
# =============================================================================
# SHIELD — recette US-05 : depuis un conteneur leurre, toute sortie doit ECHOUER
#
#   ./scripts/qa/decoy_egress.sh                 # leurres de docker compose
#   ./scripts/qa/decoy_egress.sh shield-decoy-ssh
#
# Teste TCP, UDP, DNS, HTTP et l'acces a l'hote. Seul le collecteur doit etre
# joignable (c'est la seule route autorisee hors de la zone leurre).
# Code de sortie = nombre de sorties qui ont reussi.
# =============================================================================
set -uo pipefail

containers=("$@")
if [[ ${#containers[@]} -eq 0 ]]; then
  containers=(shield-decoy-ssh shield-decoy-http shield-decoy-ftp)
fi

read -r -d '' PROBE <<'PY'
import socket, urllib.request

def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=4).close()
        return True
    except OSError:
        return False

def udp_dns():
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, ("8.8.8.8", 53))
        sock.recvfrom(512)
        return True
    except OSError:
        return False

def resolves(name):
    try:
        socket.gethostbyname(name)
        return True
    except OSError:
        return False

def http(url):
    try:
        urllib.request.urlopen(url, timeout=4)
        return True
    except Exception:
        return False

# (description, a reussi ?, doit reussir ?)
checks = [
    ("TCP 1.1.1.1:443", tcp("1.1.1.1", 443), False),
    ("TCP 8.8.8.8:53", tcp("8.8.8.8", 53), False),
    ("UDP 8.8.8.8:53", udp_dns(), False),
    ("resolution DNS example.com", resolves("example.com"), False),
    ("HTTP 1.1.1.1", http("http://1.1.1.1/"), False),
    ("hote via host.docker.internal:80", tcp("host.docker.internal", 80), False),
    ("collector:8000 (seule route autorisee)", tcp("collector", 8000), True),
]
gaps = 0
for name, ok, expected in checks:
    good = ok == expected
    gaps += not good
    state = "ouvert" if ok else "bloque"
    print(("OK    " if good else "ECART ") + f"{name} : {state}")
raise SystemExit(gaps)
PY

total=0
for container in "${containers[@]}"; do
  echo "== $container"
  if ! docker inspect "$container" >/dev/null 2>&1; then
    echo "ECART conteneur introuvable"
    total=$((total + 1))
    continue
  fi
  docker exec -i "$container" python - <<<"$PROBE"
  total=$((total + $?))
done

echo
echo "$total ecart(s)"
exit "$total"
