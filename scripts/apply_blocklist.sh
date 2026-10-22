#!/usr/bin/env bash
# =============================================================================
# SHIELD — défense active : protège les VRAIS services avec la liste de blocage
#
#   sudo ./scripts/apply_blocklist.sh             # applique (DRY_RUN=0 dans la config)
#   sudo DRY_RUN=1 ./scripts/apply_blocklist.sh   # affiche et vérifie, n'applique rien
#
# Le honeypot apprend qui attaque ; ce script s'en sert pour fermer à ces adresses
# les ports des services réels de la machine (tableau de bord, vrai SSH…).
#
# Il ne bloque JAMAIS les ports des leurres : un honeypot qui refuse les attaquants
# ne sert plus à rien. Il refuse donc de démarrer si un port protégé est un port de
# leurre, ou si aucune liste blanche n'est définie (risque de s'enfermer dehors).
#
# Sûreté :
#   - chaque adresse reçue est validée ; toute ligne douteuse est ignorée ;
#   - les adresses privées, de bouclage et locales ne sont jamais bloquées ;
#   - liste injoignable → rien ne change, les règles en place restent ;
#   - les règles sont remplacées atomiquement (nft -f), dans une table dédiée
#     (inet shield_defense) qu'on supprime d'une commande :
#         sudo nft delete table inet shield_defense
#
# Configuration : /etc/shield/blocklist.env (root, chmod 600), voir
# deploy/systemd/blocklist.env.example. Exécution périodique : deploy/systemd/.
# =============================================================================
set -euo pipefail

CONFIG=${SHIELD_BLOCKLIST_CONFIG:-/etc/shield/blocklist.env}
if [[ -f "$CONFIG" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG"
fi

SHIELD_URL=${SHIELD_URL:-https://127.0.0.1:8443}
BLOCKLIST_TOKEN=${BLOCKLIST_TOKEN:-}
# Ports tels que le client les vise, côté hôte (avant toute traduction par Docker).
PROTECTED_PORTS=${PROTECTED_PORTS:-8443}
DECOY_PORTS=${DECOY_PORTS:-22 80 21 443}
ALLOWLIST=${ALLOWLIST:-}
MIN_SCORE=${MIN_SCORE:-60}
DAYS=${DAYS:-7}
MAX_ENTRIES=${MAX_ENTRIES:-5000}
DRY_RUN=${DRY_RUN:-1}
CURL_OPTS=${CURL_OPTS:-}
NFT=${NFT:-nft}
TABLE="shield_defense"

log() { echo "apply_blocklist: $*" >&2; }
die() { log "REFUS : $*"; exit 1; }

# ------------------------------------------------------------- garde-fous
[[ -n "$BLOCKLIST_TOKEN" ]] || die "BLOCKLIST_TOKEN manquant"
[[ -n "$ALLOWLIST" || "${FORCE:-0}" == 1 ]] ||
  die "ALLOWLIST vide : ajoutez au moins votre adresse d'administration (ou FORCE=1)"
[[ "$MIN_SCORE" =~ ^[0-9]+$ && "$DAYS" =~ ^[0-9]+$ && "$MAX_ENTRIES" =~ ^[0-9]+$ ]] ||
  die "MIN_SCORE, DAYS et MAX_ENTRIES doivent être des entiers"

ports=()
for port in $PROTECTED_PORTS; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    die "port invalide : $port"
  fi
  for decoy in $DECOY_PORTS; do
    [[ "$port" != "$decoy" ]] || die "le port $port est un port de leurre : on ne bloque pas un honeypot"
  done
  ports+=("$port")
done
((${#ports[@]} > 0)) || die "PROTECTED_PORTS vide"

# ------------------------------------------------------------- validation
is_ipv4() {
  local ip=$1 octet
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  for octet in "${octets[@]}"; do ((10#$octet <= 255)) || return 1; done
}

# Une adresse que nft refuserait (« :::::: ») ferait échouer TOUTE mise à jour (#99) :
# au plus un « :: », pas de « : » isolé en bord, 8 groupes de 1 à 4 chiffres hexadécimaux.
is_ipv6() {
  local ip=${1,,} group count=0
  [[ ${#ip} -le 39 && "$ip" == *:* && "$ip" =~ ^[0-9a-f:]+$ ]] || return 1
  [[ "$ip" != *:::* ]] || return 1
  local rest=${ip/::/}
  [[ "$rest" != *::* ]] || return 1
  if [[ "$ip" == :* && "$ip" != ::* ]] || [[ "$ip" == *: && "$ip" != *:: ]]; then
    return 1
  fi
  IFS=: read -r -a groups <<<"$ip"
  for group in "${groups[@]}"; do
    [[ -n "$group" ]] || continue
    ((${#group} <= 4)) || return 1
    count=$((count + 1))
  done
  if [[ "$ip" == *::* ]]; then ((count <= 7)); else ((count == 8)); fi
}

# Jamais bloquées : privées (RFC 1918), bouclage, locales, CGNAT, multidiffusion.
is_reserved() {
  local ip=${1,,}
  case "$ip" in
    10.* | 127.* | 0.* | 169.254.* | 192.168.* | 22[4-9].* | 23[0-9].* | 24[0-9].* | 25[0-5].*) return 0 ;;
    ::1 | :: | fe[89ab]?:* | fc*:* | fd*:* | ff*:*) return 0 ;;
  esac
  if [[ "$ip" =~ ^172\.([0-9]+)\. ]] && ((BASH_REMATCH[1] >= 16 && BASH_REMATCH[1] <= 31)); then
    return 0
  fi
  if [[ "$ip" =~ ^100\.([0-9]+)\. ]] && ((BASH_REMATCH[1] >= 64 && BASH_REMATCH[1] <= 127)); then
    return 0
  fi
  return 1
}

is_allow_entry() { [[ "$1" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]]; }

# ------------------------------------------------------------- récupération
url="${SHIELD_URL%/}/api/v1/blocklist?min_score=${MIN_SCORE}&days=${DAYS}"
# shellcheck disable=SC2086  # CURL_OPTS est volontairement découpé (--cacert fichier…)
if ! body=$(curl -fsS --max-time 20 $CURL_OPTS -H "X-Blocklist-Token: ${BLOCKLIST_TOKEN}" "$url"); then
  log "liste injoignable : règles en place inchangées"
  exit 2
fi

hostile4=() hostile6=() rejected=0
while IFS= read -r line; do
  ip=${line//[[:space:]]/}
  [[ -n "$ip" ]] || continue
  if is_ipv4 "$ip"; then
    is_reserved "$ip" || hostile4+=("$ip")
  elif is_ipv6 "$ip"; then
    is_reserved "$ip" || hostile6+=("${ip,,}")
  else
    rejected=$((rejected + 1))
  fi
  ((${#hostile4[@]} + ${#hostile6[@]} < MAX_ENTRIES)) || break
done <<<"$body"
((rejected == 0)) || log "$rejected ligne(s) invalide(s) ignorée(s)"

allow4=() allow6=()
for entry in $ALLOWLIST; do
  is_allow_entry "$entry" || die "entrée de liste blanche invalide : $entry"
  if [[ "$entry" == *:* ]]; then allow6+=("$entry"); else allow4+=("$entry"); fi
done

# ------------------------------------------------------------- jeu de règles
join() { local IFS=,; echo "$*"; }
elements() {
  if (($# > 0)); then echo "elements = { $(join "$@") }"; fi
}

port_set=$(join "${ports[@]}")
ruleset=$(mktemp)
trap 'rm -f "$ruleset"' EXIT
{
  echo "add table inet $TABLE"
  echo "delete table inet $TABLE"
  echo "table inet $TABLE {"
  echo "  set allow4 { type ipv4_addr; flags interval; auto-merge; $(elements "${allow4[@]}") }"
  echo "  set allow6 { type ipv6_addr; flags interval; auto-merge; $(elements "${allow6[@]}") }"
  echo "  set hostile4 { type ipv4_addr; $(elements "${hostile4[@]}") }"
  echo "  set hostile6 { type ipv6_addr; $(elements "${hostile6[@]}") }"
  # input : services de l'hôte ; forward : ports publiés par Docker. Dans forward, le
  # port a déjà été réécrit par le DNAT de Docker (22 → 2222 du relais des leurres) :
  # on filtre donc sur le port D'ORIGINE, celui que vise le client (#99).
  for hook in input forward; do
    echo "  chain $hook {"
    echo "    type filter hook $hook priority filter - 10; policy accept;"
    echo "    ip saddr @allow4 return"
    echo "    ip6 saddr @allow6 return"
    echo "    meta l4proto tcp ct original proto-dst { $port_set } ip saddr @hostile4 counter drop"
    echo "    meta l4proto tcp ct original proto-dst { $port_set } ip6 saddr @hostile6 counter drop"
    echo "  }"
  done
  echo "}"
} >"$ruleset"

summary="${#hostile4[@]} IPv4 + ${#hostile6[@]} IPv6 bloquées sur les ports ${port_set}"
if [[ "$DRY_RUN" == 1 ]]; then
  cat "$ruleset"
  "$NFT" -c -f "$ruleset" && log "essai (DRY_RUN=1), règles valides : $summary — rien n'est appliqué"
  exit 0
fi
"$NFT" -f "$ruleset"
log "appliqué : $summary"
