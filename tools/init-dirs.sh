#!/usr/bin/env sh
# Crée les dossiers écrits par les conteneurs et les rend inscriptibles :
#   data/cowrie  -> Cowrie tourne en uid 999 (journal cowrie.json)
#   out          -> n8n tourne en uid 1000 (journaux des workflows, règles générées dans out/ia)
# Le chmod 777 est acceptable sur un poste de TP jetable ; sur une vraie plateforme on utiliserait chown uid:gid.
# Usage : sh tools/init-dirs.sh   (à lancer depuis plateforme/, AVANT le premier `docker compose up -d`)
set -eu
cd "$(dirname "$0")/.."
mkdir -p data/cowrie out/ia rules/yara rules/sigma livrables
chmod -R 777 data/cowrie out
touch out/.gitkeep
echo "OK : data/cowrie et out/ créés et inscriptibles (777). Vous pouvez lancer : docker compose up -d"
