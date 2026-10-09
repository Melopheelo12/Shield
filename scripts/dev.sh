#!/usr/bin/env bash
# =============================================================================
# SHIELD — environnement de développement en une commande
#
#   make dev                      # ou ./scripts/dev.sh
#   RATE=10 make dev              # 10 tentatives factices par seconde
#   SHIELD_STORAGE=postgres DATABASE_URL=... make dev   # sur une vraie base
#
# Lance le collecteur (en mémoire par défaut : aucune base à installer), le
# générateur d'attaques factices et le tableau de bord, puis ouvre
# http://localhost:5173. Ctrl+C arrête les trois.
#
# Aucun leurre n'est exposé : les attaques sont simulées, en local seulement.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

# Fixe : le proxy de dashboard/vite.config.ts vise le collecteur sur :8000.
API_PORT=8000
UI_PORT="${UI_PORT:-5173}"
RATE="${RATE:-3}"
STORAGE="${SHIELD_STORAGE:-memory}"
TOKEN="dev-token"

die() { echo "ERREUR : $*" >&2; exit 1; }

[[ -x .venv/bin/python ]] || die "environnement Python absent : lancez d'abord 'make install'."
command -v npm >/dev/null || die "npm introuvable : installez Node.js 20."
for port in "$API_PORT" "$UI_PORT"; do
  if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    die "le port $port est déjà utilisé (un 'make dev' tourne déjà ?)."
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

echo "==> Tableau de bord sur http://localhost:$UI_PORT"
(cd dashboard && exec npx vite --port "$UI_PORT" --strictPort --clearScreen false) &
pids+=($!)

if [[ "$(uname)" == "Darwin" ]]; then
  (sleep 3 && open "http://localhost:$UI_PORT") &
fi

echo
echo "Ctrl+C pour tout arrêter."
wait
