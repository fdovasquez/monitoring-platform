#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_DIR/agents/dist/linux"

mkdir -p "$DIST_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: Go es requerido solo en el servidor de monitoreo para compilar el paquete."
  echo "En Ubuntu: sudo apt install -y golang-go"
  exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags="-s -w" \
  -o "$DIST_DIR/monitoring-agent-linux-x86_64" \
  "$SCRIPT_DIR/standalone/main.go"

chmod 755 "$DIST_DIR/monitoring-agent-linux-x86_64"

echo "Agente standalone generado en: $DIST_DIR/monitoring-agent-linux-x86_64"

