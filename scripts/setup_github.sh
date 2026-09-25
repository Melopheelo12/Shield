#!/usr/bin/env bash
# =============================================================================
# SHIELD — mise en place du dépôt GitHub (tâche S0-02 et S0-03 du sprint 0)
#
# Crée les labels, les 49 issues du backlog, les jalons, le board de projet et
# applique la protection de la branche main.
#
# Prérequis : gh (GitHub CLI) authentifié — `gh auth login`
#
#   ./scripts/setup_github.sh --repo ryan/shield            # tout
#   ./scripts/setup_github.sh --repo ryan/shield --dry-run  # simulation
#   ./scripts/setup_github.sh --repo ryan/shield --only labels
#
# Le script est IDEMPOTENT : le relancer ne crée pas de doublon.
# =============================================================================
set -euo pipefail

REPO=""
DRY_RUN=false
ONLY="all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)    REPO="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --only)    ONLY="$2"; shift 2 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done

[[ -z "$REPO" ]] && { echo "usage: $0 --repo <owner/name> [--dry-run] [--only labels|issues|milestones|protection]" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh (GitHub CLI) est requis : https://cli.github.com" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 est requis" >&2; exit 1; }

BACKLOG=".github/backlog.json"
[[ -f "$BACKLOG" ]] || { echo "$BACKLOG introuvable — lancez le script depuis la racine du dépôt" >&2; exit 1; }

run() {
  if $DRY_RUN; then echo "  [dry-run] $*"; else "$@"; fi
}

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# --------------------------------------------------------------------- labels
create_labels() {
  section "Labels"
  # nom|couleur|description
  local labels=(
    "epic:A-capture|1d76db|Capture et journalisation (F1)"
    "epic:B-enrichissement|1d76db|Enrichissement et qualification (F2)"
    "epic:C-agent-defenseur|1d76db|Agent défenseur (F3)"
    "epic:D-tableau-de-bord|1d76db|Tableau de bord et alertes (F4)"
    "epic:E-sandbox|1d76db|Sandbox attaque-défense (F5)"
    "epic:F-veille|1d76db|Agent de veille (F6)"
    "epic:G-export|1d76db|Export et liste de blocage (F7)"
    "epic:H-deploiement|1d76db|Déploiement et conformité"
    "prio:must|b60205|Must have — sans elle, il n'y a pas de produit"
    "prio:should|d93f0b|Should have — sacrifiable en dernier recours"
    "prio:could|fbca04|Could have — sacrifiée en premier"
    "sprint:0|c5def5|Sprint 0 — fondations (S6)"
    "sprint:1|c5def5|Sprint 1 — capture (S7)"
    "sprint:2|c5def5|Sprint 2 — enrichissement et agent (S8)"
    "sprint:3|c5def5|Sprint 3 — tableau de bord (S9)"
    "sprint:4|c5def5|Sprint 4 — alertes et options (S10)"
    "lane:backend|0e8a16|Ryan — back-end et sécurité"
    "lane:frontend|5319e7|Antho — front-end et DevOps"
    "type:bug|d73a4a|Défaut constaté"
    "type:security|b60205|Touche la sécurité — revue renforcée obligatoire"
    "type:docs|0075ca|Documentation"
    "type:chore|cfd3d7|Outillage, CI, maintenance"
    "blocked|000000|Bloquée par une dépendance"
  )
  for entry in "${labels[@]}"; do
    IFS='|' read -r name color desc <<< "$entry"
    if gh label list --repo "$REPO" --limit 200 | grep -qF "$name"; then
      run gh label edit "$name" --repo "$REPO" --color "$color" --description "$desc"
    else
      run gh label create "$name" --repo "$REPO" --color "$color" --description "$desc"
    fi
  done
}

# ------------------------------------------------------------------- jalons
create_milestones() {
  section "Jalons"
  # titre|description
  local milestones=(
    "J4 — Environnement opérationnel (fin S6)|Le serveur est en ligne, durci, et le premier leurre collecte."
    "J5 — Capture sans perte (fin S7)|Les trois leurres capturent 100 % des tentatives, sans perte jusqu'à 50 év./s."
    "J6 — Enrichissement et verdict (fin S8)|Les données sont enrichies et l'agent produit un verdict explicable."
    "J7 — MVP complet (fin S10)|Produit complet et démontrable. Plus aucune nouvelle fonctionnalité."
  )
  for entry in "${milestones[@]}"; do
    IFS='|' read -r title desc <<< "$entry"
    if gh api "repos/$REPO/milestones" --jq '.[].title' 2>/dev/null | grep -qF "$title"; then
      echo "  déjà présent : $title"
    else
      run gh api "repos/$REPO/milestones" -f title="$title" -f description="$desc" --silent
    fi
  done
}

# ------------------------------------------------------------------- issues
create_issues() {
  section "Issues (49 user stories)"
  local existing
  existing=$(gh issue list --repo "$REPO" --limit 300 --state all --json title --jq '.[].title' || true)

  python3 - "$BACKLOG" > /tmp/shield_issues.tsv <<'PY'
import json, sys
SPRINT = {"F1":"1","F2":"2","F3":"2","F4":"3","F5":"4","F6":"4","F7":"4","transverse":"0"}
LANE = {"D-tableau-de-bord":"frontend","E-sandbox":"frontend"}
for s in json.load(open(sys.argv[1], encoding="utf-8")):
    title = f"{s['id']} — {s['epic_title']}"
    body = [
        "## Story", "", s["story"], "",
        "## Critères d'acceptation", "",
        *[f"- [ ] {c}" for c in s["criteria"]], "",
        f"**Épopée :** {s['epic_title']} ({s['feature']})  ",
        f"**Priorité MoSCoW :** {s['priority']}", "",
        "## Definition of Done", "",
        "- [ ] Code fusionné dans `main`",
        "- [ ] Tests associés au vert",
        "- [ ] Documentation à jour",
        "- [ ] Déployé sur l'environnement de démonstration",
        "- [ ] L'autre membre a pu le faire fonctionner de son côté",
        "",
        "_Issue générée depuis le backlog de l'étape 3 (documentation technique)._",
    ]
    labels = [
        f"epic:{s['epic']}",
        f"prio:{s['priority'].lower()}",
        f"sprint:{SPRINT[s['feature']]}",
        f"lane:{LANE.get(s['epic'], 'backend')}",
    ]
    print("\t".join([title, ",".join(labels), "\\n".join(body)]))
PY

  local created=0 skipped=0
  while IFS=$'\t' read -r title labels body; do
    if grep -qxF "$title" <<< "$existing"; then
      skipped=$((skipped+1)); continue
    fi
    # shellcheck disable=SC2059
    printf -v real_body "$body"
    run gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$real_body"
    created=$((created+1))
  done < /tmp/shield_issues.tsv
  rm -f /tmp/shield_issues.tsv
  echo "  créées : $created · déjà présentes : $skipped"
}

# -------------------------------------------------------- protection de main
protect_main() {
  section "Protection de la branche main"
  local payload
  payload=$(cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Lint & types", "Tests unitaires", "Contrat d'evenement", "Securite"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
)
  if $DRY_RUN; then
    echo "  [dry-run] PUT repos/$REPO/branches/main/protection"
    echo "$payload" | head -5
  else
    echo "$payload" | gh api -X PUT "repos/$REPO/branches/main/protection" --input - --silent
    echo "  protection appliquée"
  fi
}

# --------------------------------------------------------------------- board
create_project() {
  section "Board de projet"
  echo "  GitHub Projects (v2) ne se crée pas de façon fiable en ligne de commande."
  echo "  À faire à la main, une fois, puis lier les issues :"
  echo "    1. https://github.com/$REPO → onglet Projects → New project → Board"
  echo "    2. Colonnes : Backlog / À faire / En cours / En revue / Terminé"
  echo "    3. Champs personnalisés : Sprint (nombre), Points (nombre), Lane (texte)"
  echo "    4. Workflow automatique : « Item closed » → Terminé"
}

case "$ONLY" in
  all)         create_labels; create_milestones; create_issues; protect_main; create_project ;;
  labels)      create_labels ;;
  milestones)  create_milestones ;;
  issues)      create_issues ;;
  protection)  protect_main ;;
  project)     create_project ;;
  *) echo "valeur --only inconnue : $ONLY" >&2; exit 2 ;;
esac

section "Terminé"
$DRY_RUN && echo "(simulation — rien n'a été modifié)"
exit 0
