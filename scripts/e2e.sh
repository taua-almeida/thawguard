#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="thawguard-e2e"
KEEP_ON_FAILURE="${E2E_KEEP_ON_FAILURE:-0}"
COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$ROOT_DIR/compose.yaml" --file "$ROOT_DIR/compose.local.yaml")

cd "$ROOT_DIR"

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT INT TERM

  if [[ $status -ne 0 && "$KEEP_ON_FAILURE" == "1" ]]; then
    printf 'E2E failed; keeping Compose project %s for debugging.\n' "$PROJECT_NAME" >&2
    printf 'Clean it with: docker compose --project-name %q --file %q --file %q down --volumes --remove-orphans\n' \
      "$PROJECT_NAME" "$ROOT_DIR/compose.yaml" "$ROOT_DIR/compose.local.yaml" >&2
  else
    "${COMPOSE[@]}" down --volumes --remove-orphans || cleanup_status=$?
  fi

  if [[ $status -eq 0 && $cleanup_status -ne 0 ]]; then
    status=$cleanup_status
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in docker go openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  printf 'Docker Compose is unavailable.\n' >&2
  exit 1
fi

export THAWGUARD_SECRET_KEY="$(openssl rand -base64 32)"
export THAWGUARD_PUBLIC_URL="http://127.0.0.1:8080"

# Remove only this disposable project's containers and volumes before checking
# the shared loopback ports. A persistent thawguard-local stack is never removed.
"${COMPOSE[@]}" down --volumes --remove-orphans
for port in 3000 8080; do
  if (exec 9<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    printf 'loopback port %s is already in use; stop the other local stack or process before running E2E.\n' "$port" >&2
    exit 1
  fi
done

"${COMPOSE[@]}" up --build --detach --wait --wait-timeout 180

if [[ "${E2E_FAIL_AFTER_START:-0}" == "1" ]]; then
  printf 'intentional E2E failure requested after stack startup.\n' >&2
  exit 97
fi

thawguard_admin_password="$(openssl rand -hex 24)"
webhook_secret="$(openssl rand -hex 32)"

forgejo_admin() {
  "${COMPOSE[@]}" exec --no-TTY --user git forgejo \
    forgejo --work-path /data/gitea --config /data/gitea/conf/app.ini admin user "$@"
}

forgejo_admin create \
  --username e2e-admin \
  --random-password \
  --random-password-length 24 \
  --email e2e-admin@thawguard.test \
  --admin \
  --must-change-password=false >/dev/null

forgejo_admin create \
  --username e2e-owner \
  --random-password \
  --random-password-length 24 \
  --email e2e-owner@thawguard.test \
  --must-change-password=false >/dev/null

forgejo_token="$(forgejo_admin generate-access-token \
  --username e2e-owner \
  --token-name thawguard-e2e \
  --scopes write:repository,write:user \
  --raw)"
if [[ -z "$forgejo_token" ]]; then
  printf 'Forgejo did not return an access token.\n' >&2
  exit 1
fi

THAWGUARD_E2E=1 \
THAWGUARD_E2E_FORGEJO_URL="http://127.0.0.1:3000" \
THAWGUARD_E2E_FORGEJO_TOKEN="$forgejo_token" \
THAWGUARD_E2E_WEBHOOK_SECRET="$webhook_secret" \
THAWGUARD_E2E_ADMIN_PASSWORD="$thawguard_admin_password" \
  go test -tags=e2e ./internal/e2e -count=1 -v
