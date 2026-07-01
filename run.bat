@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv" (
  echo Virtual environment not found. Run install.bat first.
  pause
  exit /b 1
)

echo Starting DLP Screen Analyzer...
echo Dashboard: http://127.0.0.1:8000
echo Press Ctrl+C to stop.
echo.

start "" http://127.0.0.1:8000
cd backend
"..\.venv\Scripts\python.exe" main.py
