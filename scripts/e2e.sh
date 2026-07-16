#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="thawguard-e2e"
KEEP_ON_FAILURE="${E2E_KEEP_ON_FAILURE:-0}"
COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$ROOT_DIR/compose.yaml" --file "$ROOT_DIR/compose.local.yaml")
test_output=""
container_log_output=""
forgejo_control_token=""
forgejo_owner_password=""
primary_status_token=""
replacement_status_token=""
forbidden_values=()

cd "$ROOT_DIR"

new_private_temp_file() {
  mktemp "${TMPDIR:-/tmp}/thawguard-e2e.XXXXXX"
}

scan_file_for_sensitive_values() {
  local file=$1
  local surface=$2
  local token line

  [[ -f "$file" ]] || return 0
  for token in "${forbidden_values[@]}"; do
    [[ -n "$token" ]] || continue
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" == *"$token"* ]]; then
        printf 'sensitive value detected in %s; unsafe output withheld.\n' "$surface" >&2
        return 1
      fi
    done <"$file"
  done
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local log_scan_status=0
  trap - EXIT INT TERM

  if [[ -z "$container_log_output" ]]; then
    container_log_output="$(new_private_temp_file)" || log_scan_status=1
  fi
  if [[ -n "$container_log_output" ]]; then
    if "${COMPOSE[@]}" logs --no-color >"$container_log_output" 2>&1; then
      scan_file_for_sensitive_values "$container_log_output" "container logs" || log_scan_status=$?
    else
      printf 'could not capture container logs for redaction scan.\n' >&2
      log_scan_status=1
    fi
  fi
  if [[ $status -eq 0 && $log_scan_status -ne 0 ]]; then
    status=$log_scan_status
  fi

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
  [[ -z "$test_output" ]] || rm -f -- "$test_output"
  [[ -z "$container_log_output" ]] || rm -f -- "$container_log_output"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in docker go openssl mktemp; do
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
forbidden_values+=("$THAWGUARD_SECRET_KEY")

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
forbidden_values+=("$thawguard_admin_password" "$webhook_secret")

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

owner_create_output="$(forgejo_admin create \
  --username e2e-owner \
  --random-password \
  --random-password-length 24 \
  --email e2e-owner@thawguard.test \
  --must-change-password=false)"
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ generated\ random\ password\ is\ \'([^\']+)\' ]]; then
    forgejo_owner_password="${BASH_REMATCH[1]}"
    break
  fi
done <<<"$owner_create_output"
unset owner_create_output line
if [[ -z "$forgejo_owner_password" ]]; then
  printf 'Forgejo did not return the generated repository-owner password in the expected format.\n' >&2
  exit 1
fi
forbidden_values+=("$forgejo_owner_password")

forgejo_control_token="$(forgejo_admin generate-access-token \
  --username e2e-owner \
  --token-name thawguard-e2e-control \
  --scopes write:repository,write:user \
  --raw)"
if [[ -z "$forgejo_control_token" ]]; then
  printf 'Forgejo did not return the control access token.\n' >&2
  exit 1
fi
forbidden_values+=("$forgejo_control_token")

primary_status_token="$(forgejo_admin generate-access-token \
  --username e2e-owner \
  --token-name thawguard-e2e-status-primary \
  --scopes write:repository \
  --raw)"
if [[ -z "$primary_status_token" ]]; then
  printf 'Forgejo did not return the primary status token.\n' >&2
  exit 1
fi
forbidden_values+=("$primary_status_token")

replacement_status_token="$(forgejo_admin generate-access-token \
  --username e2e-owner \
  --token-name thawguard-e2e-status-replacement \
  --scopes write:repository \
  --raw)"
if [[ -z "$replacement_status_token" ]]; then
  printf 'Forgejo did not return the replacement status token.\n' >&2
  exit 1
fi
forbidden_values+=("$replacement_status_token")

test_output="$(new_private_temp_file)"
test_status=0

if THAWGUARD_E2E=1 \
  THAWGUARD_E2E_FORGEJO_URL="http://127.0.0.1:3000" \
  THAWGUARD_E2E_FORGEJO_CONTROL_TOKEN="$forgejo_control_token" \
  THAWGUARD_E2E_FORGEJO_OWNER_PASSWORD="$forgejo_owner_password" \
  THAWGUARD_E2E_PRIMARY_STATUS_TOKEN="$primary_status_token" \
  THAWGUARD_E2E_REPLACEMENT_STATUS_TOKEN="$replacement_status_token" \
  THAWGUARD_E2E_WEBHOOK_SECRET="$webhook_secret" \
  THAWGUARD_E2E_ADMIN_PASSWORD="$thawguard_admin_password" \
    go test -tags=e2e ./internal/e2e -count=1 -v >"$test_output" 2>&1; then
  test_status=0
else
  test_status=$?
fi

if ! scan_file_for_sensitive_values "$test_output" "go test output"; then
  if [[ $test_status -ne 0 ]]; then
    exit "$test_status"
  fi
  exit 1
fi
cat -- "$test_output"
exit "$test_status"
