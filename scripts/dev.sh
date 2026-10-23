#!/usr/bin/env bash
# =============================================================================
# SHIELD — environnement de développement en une commande
#
#   make dev                      # ou ./scripts/dev.sh
#   RATE=10 make dev              # 10 tentatives factices par seconde
#   SHIELD_STORAGE=postgres DATABASE_URL=... make dev   # sur une vraie base
#   make demo                     # + leurre WordPress sur :8080, flux factice réduit
#
# Lance le collecteur (en mémoire par défaut : aucune base à installer), le
# générateur d'attaques factices et le tableau de bord, puis ouvre
# http://localhost:5173. Ctrl+C arrête tout.
#
# Sans DEMO_DECOY_PORT, aucun leurre n'est lancé : les attaques sont simulées.
# Avec (make demo), le leurre HTTP tourne sur cette machine pour attaquer le
# site à la main pendant une présentation et voir l'attaque arriver en direct.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

# Fixe : le proxy de dashboard/vite.config.ts vise le collecteur sur :8000.
API_PORT=8000
UI_PORT="${UI_PORT:-5173}"
RATE="${RATE:-3}"
STORAGE="${SHIELD_STORAGE:-memory}"
DECOY_PORT="${DEMO_DECOY_PORT:-}"
TOKEN="dev-token"
# Compte de développement du tableau de bord (US-19), pour ce lancement local
# seulement : en production, ADMIN_PASSWORD vient du .env.
ADMIN_USER="admin"
ADMIN_PASS="dev-admin"

die() { echo "ERREUR : $*" >&2; exit 1; }

[[ -x .venv/bin/python ]] || die "environnement Python absent : lancez d'abord 'make install'."
command -v npm >/dev/null || die "npm introuvable : installez Node.js 20."
for port in "$API_PORT" "$UI_PORT" $DECOY_PORT; do
  if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    die "le port $port est déjà utilisé (un 'make dev' ou 'make demo' tourne déjà ?)."
  fi
done

if [[ ! -d dashboard/node_modules ]]; then
  echo "==> Installation des dépendances du tableau de bord"
  (cd dashboard && npm ci)
fi

pids=()
cleanup() {
  trap - EXIT INT TERM
  echo
  echo "==> Arrêt"
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Collecteur sur :$API_PORT (stockage : $STORAGE)"
INGEST_TOKEN="$TOKEN" SHIELD_STORAGE="$STORAGE" SHIELD_ENV=dev \
  ADMIN_USERNAME="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASS" \
  .venv/bin/uvicorn shield.collector.api.app:app --port "$API_PORT" --log-level warning &
pids+=($!)

for _ in $(seq 1 40); do
  curl -sf "http://localhost:$API_PORT/api/v1/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://localhost:$API_PORT/api/v1/health" >/dev/null || die "le collecteur n'a pas démarré."

echo "==> Attaques factices : $RATE par seconde"
.venv/bin/python -m shield.tools.fake_events --token "$TOKEN" --rate "$RATE" \
  --url "http://localhost:$API_PORT/api/v1/ingest" >/dev/null 2>&1 &
pids+=($!)

if [[ -n "$DECOY_PORT" ]]; then
  echo "==> Leurre WordPress sur http://localhost:$DECOY_PORT (à attaquer à la main)"
  INGEST_TOKEN="$TOKEN" COLLECTOR_INGEST_URL="http://localhost:$API_PORT/api/v1/ingest" \
    .venv/bin/python -m shield.decoys.runner http --port "$DECOY_PORT" >/dev/null 2>&1 &
  pids+=($!)
fi

echo "==> Tableau de bord sur http://localhost:$UI_PORT (connexion : $ADMIN_USER / $ADMIN_PASS)"
(cd dashboard && exec npx vite --port "$UI_PORT" --strictPort --clearScreen false) &
pids+=($!)

if [[ "$(uname)" == "Darwin" ]]; then
  (sleep 3 && open "http://localhost:$UI_PORT") &
fi

echo
echo "Ctrl+C pour tout arrêter."
wait
