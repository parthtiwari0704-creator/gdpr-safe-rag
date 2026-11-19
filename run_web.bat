@echo off
cd /d "%~dp0"
echo Starting GDPR-safe Document Assistant...
.venv\Scripts\python.exe web.py
pause
