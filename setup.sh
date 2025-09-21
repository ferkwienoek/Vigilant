#!/bin/sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install semgrep
python -m spacy download en_core_web_sm
npm install
echo "Setup done. Run: . .venv/bin/activate && python context_service.py & && node server.js"
