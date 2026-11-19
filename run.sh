#!/usr/bin/env bash
# One-click setup and launch on macOS / Linux
set -e
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
streamlit run app.py
