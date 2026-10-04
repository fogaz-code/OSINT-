#!/usr/bin/env bash
# Crea l'eseguibile standalone con PyInstaller e lo verifica fuori dal repository.
# Prerequisito (in un venv): pip install ".[build]"
# Uso: scripts/build-binary.sh  ->  dist/secure-osint  (dist/secure-osint.exe su Windows)
# Va eseguito sullo stesso sistema operativo di destinazione: un build Linux non gira su Windows.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo 'pyinstaller not found: run  pip install ".[build]"  in your virtual environment first.' >&2
  exit 1
fi

# --collect-all secure_osint: include i workflow YAML (package data) e tutti i sottomoduli.
# Entry point: __main__.py, NON cli.py (altrimenti cli.py girerebbe come __main__ e cercherebbe i
# workflow nel posto sbagliato dentro il binario).
pyinstaller --noconfirm --clean --onefile --name secure-osint \
  --collect-all secure_osint \
  --workpath build/pyinstaller --specpath build/pyinstaller \
  src/secure_osint/__main__.py

bin="$PWD/dist/secure-osint"
[ -f "$bin.exe" ] && bin="$bin.exe"

# Smoke test da una directory temporanea: fallisce se i workflow non sono dentro il binario.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$tmp" && "$bin" dry-run example.com >/dev/null)
echo "OK: $bin (workflows bundled, runs outside the repository)"
