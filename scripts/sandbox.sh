#!/usr/bin/env bash
# =============================================================================
# SHIELD — pilote de la sandbox attaque-defense (US-34, US-35, US-38)
#
#   ./scripts/sandbox.sh start [--scenario bruteforce-ssh]
#   ./scripts/sandbox.sh attacker      # shell dans le conteneur attaquant
#   ./scripts/sandbox.sh report
#   ./scripts/sandbox.sh stop
#
# GARDE-FOU : refuse de demarrer si SHIELD_ENV=prod. Le controle est fait AVANT
# que quoi que ce soit ne demarre — c'est l'erreur de manipulation la plus
# probable et la plus couteuse.
# =============================================================================
set -euo pipefail

COMPOSE="docker compose -f docker-compose.sandbox.yml"
RUN_FILE=".sandbox-run"

guard() {
  local env_value="${SHIELD_ENV:-dev}"
  if [[ "$env_value" == "prod" ]]; then
    echo "REFUS : SHIELD_ENV=prod." >&2
    echo "La sandbox ne doit jamais tourner sur l'hote expose a Internet." >&2
    exit 1
  fi
  if [[ -f /etc/shield-production ]]; then
    echo "REFUS : cet hote est marque comme serveur de production." >&2
    exit 1
  fi
  echo "garde-fou : OK (SHIELD_ENV=$env_value)"
}

case "${1:-}" in
  start)
    guard
    scenario="libre"
    [[ "${2:-}" == "--scenario" ]] && scenario="${3:-libre}"
    echo "demarrage de la sandbox (scenario : $scenario)"
    $COMPOSE up -d --build
    date -u +%Y-%m-%dT%H:%M:%SZ > "$RUN_FILE"
    echo "$scenario" >> "$RUN_FILE"
    echo
    echo "  Defenseur : tableau de bord sandbox sur http://localhost:8001"
    echo "  Attaquant : ./scripts/sandbox.sh attacker"
    echo "  Reseau    : sandbox_net (internal) — aucune sortie possible"
    ;;
  attacker)
    guard
    echo "Vous entrez dans le conteneur attaquant."
    echo "Cibles autorisees : UNIQUEMENT sandbox-decoy-ssh, sur ce reseau isole."
    $COMPOSE exec attacker sh
    ;;
  report)
    if [[ ! -f "$RUN_FILE" ]]; then echo "aucune partie en cours" >&2; exit 1; fi
    started=$(head -1 "$RUN_FILE"); scenario=$(tail -1 "$RUN_FILE")
    echo "Partie demarree le $started (scenario : $scenario)"
    $COMPOSE exec -T sandbox-collector \
      python -c "import urllib.request,json;print(json.dumps(json.load(urllib.request.urlopen('http://localhost:8000/api/v1/stats/overview')),indent=2))"
    ;;
  stop)
    $COMPOSE down -v
    rm -f "$RUN_FILE"
    echo "sandbox arretee, donnees d'entrainement supprimees"
    ;;
  *)
    echo "usage: $0 {start|attacker|report|stop}" >&2
    exit 2
    ;;
esac
