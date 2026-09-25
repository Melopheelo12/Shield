#!/usr/bin/env bash
# =============================================================================
# SHIELD — arret d'urgence (US-48)
#
# Coupe l'exposition Internet IMMEDIATEMENT, en conservant toutes les donnees.
# Procedure a tester au moins une fois avant la soutenance.
# =============================================================================
set -euo pipefail

echo "Arret des leurres..."
docker compose stop decoy-ssh decoy-http decoy-ftp

echo
echo "Etat apres arret :"
docker compose ps --format "table {{.Name}}\t{{.Status}}"

echo
echo "Les leurres sont arretes. La base de donnees, le collecteur et le"
echo "tableau de bord continuent de fonctionner : aucune donnee n'est perdue."
echo
echo "Pour redemarrer : docker compose start decoy-ssh decoy-http decoy-ftp"
