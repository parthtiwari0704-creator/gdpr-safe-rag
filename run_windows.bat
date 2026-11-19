@echo off
REM One-click setup and launch on Windows (uses the zero-dependency web UI)
if not exist .venv (
    py -m venv .venv || python -m venv .venv
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if not exist .env copy .env.example .env
.venv\Scripts\python.exe web.py
