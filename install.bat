@echo off
setlocal
cd /d "%~dp0"

echo ========================================
echo    DLP Screen Analyzer - Installation
echo ========================================
echo.

echo [1/3] Checking Python...
where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python not found.
  echo Install Python 3 from https://www.python.org/downloads/ and re-run.
  echo During install, tick "Add Python to PATH".
  pause
  exit /b 1
)
python --version

echo.
echo [2/3] Checking Tesseract OCR...
where tesseract >nul 2>&1
if errorlevel 1 (
  if exist "C:\Program Files\Tesseract-OCR\tesseract.exe" (
    echo Found Tesseract in C:\Program Files\Tesseract-OCR
  ) else (
    echo WARNING: Tesseract not found in PATH.
    echo Install it from: https://github.com/UB-Mannheim/tesseract/wiki
    echo During install, add the Russian language pack.
    echo After installing, re-run this script.
    pause
    exit /b 1
  )
) else (
  tesseract --version 2>&1 | findstr /i "tesseract"
)

echo.
echo [3/3] Creating virtual environment and installing packages...
if not exist ".venv" (
  python -m venv .venv
)
".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt
echo Done.

echo.
echo ========================================
echo    Installation complete!
echo ========================================
echo.
echo Next steps:
echo   1. Put JPEG screenshots into the "input" folder
echo   2. Run: run.bat
echo   3. Open browser: http://127.0.0.1:8000
echo.
pause
