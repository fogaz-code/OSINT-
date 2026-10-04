#!/usr/bin/env bash
# Replica la matrice CI in locale: per ogni versione di Python presente, un venv pulito con
# `pip install -e ".[dev]"`, poi ruff check, ruff format --check, mypy e pytest (gli stessi step
# della CI su GitHub). Uso: scripts/ci-matrix.sh [dir-venv]
set -u
cd "$(dirname "$0")/.."
VENVS="${1:-.venv-matrix}"
status=0
for v in 3.10 3.11 3.12 3.13; do
  if ! command -v "python$v" >/dev/null 2>&1; then
    echo "py$v | not installed, skipped"
    continue
  fi
  venv="$VENVS/py$v"
  [ -d "$venv" ] || "python$v" -m venv "$venv"
  if ! "$venv/bin/pip" install -q -e ".[dev]" >/dev/null 2>&1; then
    echo "py$v | INSTALL FAILED"; status=1; continue
  fi
  ruff_out=$("$venv/bin/ruff" check src tests >/dev/null 2>&1 && echo ok || echo FAIL)
  format_out=$("$venv/bin/ruff" format --check src tests >/dev/null 2>&1 && echo ok || echo FAIL)
  mypy_out=$("$venv/bin/mypy" src 2>&1 | tail -1)
  pytest_out=$("$venv/bin/pytest" -q -p no:cacheprovider 2>&1 | tail -1)
  echo "py$v | ruff $ruff_out | format $format_out | mypy: $mypy_out | pytest: $pytest_out"
  case "$ruff_out $format_out $mypy_out $pytest_out" in
    *FAIL*|*error*|*failed*) status=1 ;;
  esac
done
exit $status
