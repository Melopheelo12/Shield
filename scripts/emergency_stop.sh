#!/usr/bin/env bash
# =============================================================================
# SHIELD — arret d'urgence (US-48)
#
# Coupe l'exposition Internet IMMEDIATEMENT, en conservant toutes les donnees.
# Procedure a tester au moins une fois avant la soutenance.
#
# Les relais edge et edge-tls sont arretes aussi : sans eux, plus rien n'ecoute
# sur 22, 80, 21 ni 443 (leurres seuls arretes, ils acceptaient encore la
# connexion TCP avant de la fermer).
# =============================================================================
set -euo pipefail

# Lance depuis n'importe ou (sudo /opt/Shield/scripts/emergency_stop.sh) :
# docker compose cherche docker-compose.yml dans le dossier courant.
cd "$(dirname "$0")/.."

echo "Arret des relais et des leurres..."
docker compose stop edge edge-tls decoy-ssh decoy-http decoy-ftp

echo
echo "Etat apres arret :"
docker compose ps --format "table {{.Name}}\t{{.Status}}"

echo
echo "Les leurres sont arretes. La base de donnees, le collecteur et le"
echo "tableau de bord continuent de fonctionner : aucune donnee n'est perdue."
echo
echo "Pour redemarrer : docker compose up -d"
