#!/usr/bin/env bash
set -euo pipefail
SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SDK_DIR"
COMPOSE="docker compose -f docker-compose.e2e.yml"
ENV_FILE="$SDK_DIR/.e2e.env"
VAULT_URL="https://localhost:9443"

require_parent() {
  if [ ! -f "../docker/Dockerfile.sdk-test" ]; then
    echo "ERROR: parent repo build context missing (../docker/Dockerfile.sdk-test)." >&2
    echo "Run this from the SDK repo checked out inside the zn-vault monorepo." >&2
    exit 1
  fi
}

wait_healthy() {
  echo "Waiting for znvault:e2e to be healthy..."
  for i in $(seq 1 90); do
    if curl -fsk "$VAULT_URL/v1/health" >/dev/null 2>&1 \
       && docker exec znvault-e2e-server test -s /app/data/sdk-test.env 2>/dev/null; then
      echo "Vault healthy + seeded."; return 0
    fi
    sleep 2
  done
  echo "ERROR: vault did not become healthy/seeded in time." >&2
  $COMPOSE logs vault | tail -50 >&2
  return 1
}

cmd_up() {
  require_parent
  $COMPOSE up -d --build
  wait_healthy
  docker exec znvault-e2e-server cat /app/data/sdk-test.env > "$ENV_FILE"
  echo "Wrote $ENV_FILE"
}

cmd_down() { $COMPOSE down -v; rm -f "$ENV_FILE"; }
cmd_env()  { cat "$ENV_FILE"; }

cmd_run() {
  local keep="${1:-}"
  cmd_up
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  local code=0
  npx vitest run --config vitest.e2e.config.ts || code=$?
  if [ "$keep" != "--keep" ]; then cmd_down; fi
  return $code
}

case "${1:-run}" in
  up)   cmd_up ;;
  down) cmd_down ;;
  env)  cmd_env ;;
  run)  shift || true; cmd_run "${1:-}" ;;
  *)    echo "usage: e2e.sh {up|down|env|run [--keep]}" >&2; exit 2 ;;
esac
