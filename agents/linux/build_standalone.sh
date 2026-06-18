#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_DIR/agents/dist/linux"
BUILD_DIR="$REPO_DIR/.build/monitoring-agent-linux"

mkdir -p "$DIST_DIR" "$BUILD_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 es requerido para construir el agente standalone."
  exit 1
fi

python3 -m venv "$BUILD_DIR/.venv"
"$BUILD_DIR/.venv/bin/python" -m pip install --upgrade pip pyinstaller

"$BUILD_DIR/.venv/bin/pyinstaller" \
  --onefile \
  --name monitoring-agent-linux-x86_64 \
  --distpath "$DIST_DIR" \
  --workpath "$BUILD_DIR/work" \
  --specpath "$BUILD_DIR" \
  "$SCRIPT_DIR/agent.py"

chmod 755 "$DIST_DIR/monitoring-agent-linux-x86_64"

echo "Agente standalone generado en: $DIST_DIR/monitoring-agent-linux-x86_64"
