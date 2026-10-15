#!/usr/bin/env bash
# =============================================================================
# SHIELD — parcours de bout en bout du tableau de bord (S4-14)
#
#   make e2e                      # démarre la pile, lance les 4 parcours, arrête tout
#   E2E_SERVE_ONLY=1 make e2e     # démarre la pile seulement (Playwright lancé ailleurs)
#
# Pile jetable : collecteur en mémoire, build du tableau de bord, et un faux webhook
# Discord local qui répond 204 — le bouton « Tester » doit trouver un canal qui
# fonctionne, sans rien envoyer hors de la machine.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

API_PORT=8000
UI_PORT=5173
HOOK_PORT=9911
PYTHON=${PYTHON:-.venv/bin/python}

die() { echo "ERREUR : $*" >&2; exit 1; }
command -v "$PYTHON" >/dev/null || die "Python introuvable ($PYTHON) : lancez d'abord 'make install'."

pids=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$HOOK_PORT" <<'PY' &
import http.server, sys
class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Hook).serve_forever()
PY
pids+=($!)

INGEST_TOKEN=dev-token SHIELD_STORAGE=memory SHIELD_ENV=dev \
  ADMIN_USERNAME=admin ADMIN_PASSWORD=dev-admin \
  DISCORD_WEBHOOK_URL="http://127.0.0.1:$HOOK_PORT/webhook" DASHBOARD_URL="http://localhost:$UI_PORT" \
  "$PYTHON" -m uvicorn shield.collector.api.app:app --port "$API_PORT" --log-level warning &
pids+=($!)

# Le build de production, servi par `vite preview` (même mandataire /api et /ws
# que `vite`) : pas d'optimisation de dépendances à la volée, qui fait échouer
# un premier chargement au hasard.
(cd dashboard && npx vite build --logLevel warn)
(cd dashboard && exec npx vite preview --host "${E2E_HOST:-localhost}" --port "$UI_PORT" --strictPort) &
pids+=($!)

for _ in $(seq 1 60); do
  curl -sf "http://localhost:$UI_PORT/api/v1/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://localhost:$UI_PORT/api/v1/health" >/dev/null || die "la pile n'a pas démarré."
echo "==> Pile prête sur http://localhost:$UI_PORT"

if [[ "${E2E_SERVE_ONLY:-0}" == 1 ]]; then
  wait
else
  (cd dashboard && npx playwright test)
fi
