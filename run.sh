#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$DIR/.venv" ]; then
  echo "Виртуальное окружение не найдено. Запустите сначала: ./install.sh"
  exit 1
fi

echo "Запуск DLP Screen Analyzer..."
echo "Дашборд: http://127.0.0.1:8000"
echo "Для остановки: Ctrl+C"
echo ""

cd "$DIR/backend"
"$DIR/.venv/bin/python" main.py
