#!/bin/bash
set -e

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    DLP Screen Analyzer — Установка   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Python ──────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/4] Проверка Python...${NC}"
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}Ошибка: Python 3 не найден.${NC}"
  echo "Установите Python 3 с https://www.python.org/downloads/ и повторите."
  exit 1
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}✓ Python $PY_VER найден${NC}"

# ── Tesseract ────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/4] Проверка Tesseract OCR...${NC}"
if ! command -v tesseract &>/dev/null; then
  echo -e "${YELLOW}Tesseract не найден. Устанавливаю...${NC}"
  if command -v brew &>/dev/null; then
    brew install tesseract tesseract-lang
    echo -e "${GREEN}✓ Tesseract установлен через Homebrew${NC}"
  else
    echo -e "${RED}Homebrew не найден.${NC}"
    echo ""
    echo "Установите Tesseract вручную:"
    echo "  macOS:   brew install tesseract tesseract-lang"
    echo "  Ubuntu:  sudo apt install tesseract-ocr tesseract-ocr-rus"
    echo "  Windows: https://github.com/UB-Mannheim/tesseract/wiki"
    echo ""
    echo -e "${YELLOW}После установки Tesseract запустите install.sh снова.${NC}"
    exit 1
  fi
else
  echo -e "${GREEN}✓ Tesseract найден: $(tesseract --version 2>&1 | head -1)${NC}"
fi

# Проверяем наличие русского языка
if ! tesseract --list-langs 2>&1 | grep -q "rus"; then
  echo -e "${YELLOW}Языковой пакет русского не найден. Устанавливаю...${NC}"
  if command -v brew &>/dev/null; then
    brew install tesseract-lang
  elif command -v apt &>/dev/null; then
    sudo apt install -y tesseract-ocr-rus
  else
    echo -e "${RED}Не удалось автоматически установить русский язык для Tesseract.${NC}"
    echo "Скачайте rus.traineddata с https://github.com/tesseract-ocr/tessdata"
    echo "и поместите в папку tessdata (tesseract --tessdata-dir для проверки)."
  fi
else
  echo -e "${GREEN}✓ Русский языковой пакет доступен${NC}"
fi

# ── Virtual environment ───────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/4] Создание виртуального окружения...${NC}"
cd "$DIR"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  echo -e "${GREEN}✓ .venv создан${NC}"
else
  echo -e "${GREEN}✓ .venv уже существует${NC}"
fi

# ── Python packages ───────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/4] Установка Python-пакетов...${NC}"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo -e "${GREEN}✓ Пакеты установлены${NC}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Установка завершена!          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo "Дальнейшие шаги:"
echo "  1. Поместите JPEG-скрины в папку:  ${DIR}/input/"
echo "  2. Запустите приложение:            ./run.sh"
echo "  3. Откройте браузер:                http://127.0.0.1:8000"
echo ""
