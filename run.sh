#!/usr/bin/env bash
# Lance Mon Coffre-Fort, en créant l'environnement virtuel au premier lancement.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d ".venv" ]; then
    echo "Création de l'environnement virtuel (.venv)..."
    python3 -m venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

python -m app.main "$@"
