# Local alpha shadow-mode runbook

This runbook starts Thawguard locally with Docker and exercises real signed Codeberg pull-request webhooks against mock repositories.

Alpha scope:

- Thawguard receives signed pull-request webhooks.
- Thawguard records local delivery metadata, PR cache rows, status decisions, publication intents, and dry-run publication attempts.
- This default shadow-mode runbook does **not** post live commit statuses to Codeberg/Forgejo.
- Thawguard is cooperative enforcement for trusted teams and is not a hard security boundary.

## 1. Generate a local secret key

Create a local `.env` file. It is ignored by git.

```sh
THAWGUARD_SECRET_KEY=$(openssl rand -base64 32)
cat > .env <<EOF
THAWGUARD_SECRET_KEY=$THAWGUARD_SECRET_KEY
THAWGUARD_PUBLIC_URL=http://127.0.0.1:8080
THAWGUARD_STATUS_PUBLISHER=dry_run
THAWGUARD_LIVE_STATUS_POSTING=
THAWGUARD_LIVE_STATUS_REPOSITORIES=
EOF
```

Keep this key stable for a local alpha database. If it changes, stored webhook secrets and status-posting tokens become undecryptable.

## 2. Start the local Docker alpha

```sh
docker compose up --build
```

Open <http://127.0.0.1:8080>.

Thawguard runtime configuration is environment-variable based. The Docker Compose file sets `THAWGUARD_DB_PATH=/data/thawguard.db`, defaults `THAWGUARD_STATUS_PUBLISHER=dry_run`, and leaves the live-posting opt-in and allowlist empty; the binary does not parse `--db` or `--addr` CLI flags.

The compose file is Linux-oriented. It uses host networking so Thawguard can keep its bootstrap-only bind on `127.0.0.1:8080`. Host networking has lower network isolation than the default Docker bridge, so treat this as a local-alpha convenience only. Do not change the container to bind `0.0.0.0` while bootstrap sessions are still the only local auth.

The first build may pull Docker base images and Go modules. This runbook does not publish images or contact Codeberg during the Docker build.

To stop without deleting local state:

```sh
docker compose down
```

To delete the local alpha database volume:

```sh
docker compose down -v
```

## 3. Configure a mock repository in Thawguard

Use a throwaway Codeberg repository, not a production repository.

1. Go to `/repositories`.
2. Add the mock repository:
   - Forge: `forgejo`
   - Base URL: `https://codeberg.org`
   - Owner: your mock owner or organization
   - Repository: your mock repository name
   - Default branch: usually `main`
3. Set a webhook secret. Use a high-entropy value and save it somewhere local temporarily.
4. Optionally set a status token to exercise encrypted token storage. The alpha still uses dry-run publication and will not post statuses with this token.

No Codeberg token is needed for Alpha A shadow mode unless you want to exercise encrypted token storage in the setup UI.

## 4. Create a local freeze

1. Go to `/freezes`.
2. Create an active freeze for the target branch, for example `main`.
3. The freeze is local to Thawguard in the default dry-run configuration. Codeberg will not enforce it unless the guarded live-pilot mode is explicitly enabled for this repository.

## 5. Connect Codeberg webhooks safely

Codeberg must reach `POST /webhooks/forgejo` to send real webhooks. For local testing, use a tunnel or reverse proxy you trust, with HTTPS/TLS enabled.

Important safety rule: bootstrap sessions are local-development only. Do not expose the full Thawguard UI or any bootstrap-authenticated routes to the public internet. Prefer a tunnel/proxy that only forwards:

```text
POST /webhooks/forgejo
```

Configure the Codeberg webhook on the mock repository:

- Payload URL: `<your-public-webhook-url>/webhooks/forgejo`
- Secret: the same webhook secret saved in Thawguard
- Event: pull requests

If your tunnel cannot restrict paths, use a throwaway repository and an ephemeral tunnel URL, keep the test short, and stop the tunnel immediately after the test.

## 6. Exercise the flow

In the mock Codeberg repository:

1. Create a branch.
2. Open a pull request into the frozen branch.
3. Push another commit to the PR branch.
4. Optionally close/reopen the PR.

In Thawguard, inspect:

- `/webhooks` — signed delivery receipt and processing state.
- `/publications` — latest local publication intent and dry-run publication attempt.
- `/decisions` — local status decision history.
- `/freezes` — active freeze and audit history.

Expected alpha behavior:

- Webhook deliveries should show as verified and processed.
- Frozen-branch PRs should produce a local failure decision.
- Publication attempts should show `dry_run` / `planned`.
- Codeberg will not show a Thawguard commit status yet.

## Live-pilot guardrails

This runbook defaults to shadow mode. Live commit-status posting is only for throwaway or explicitly approved repositories.

To make Thawguard start with live posting, all of these must be true:

- `THAWGUARD_STATUS_PUBLISHER=forgejo_status`
- `THAWGUARD_LIVE_STATUS_POSTING=enabled`
- `THAWGUARD_LIVE_STATUS_REPOSITORIES=owner/name` lists exactly the throwaway or approved repositories allowed to post statuses
- `THAWGUARD_SECRET_KEY` is set to the same stable key used when status tokens were saved
- each allowed repository that should post statuses has an encrypted status token configured in `/repositories`

If a repository is not on the allowlist or is missing its status token, Thawguard records a failed `forgejo_status` attempt and does not post a status for that result. Dry-run remains the recommended mode for this local alpha runbook.

## Troubleshooting

- No row on `/webhooks`: check the public webhook URL, event type, and whether the tunnel is forwarding `POST /webhooks/forgejo`.
- Delivery row with an error: check repository owner/name/base URL and whether the webhook secret in Thawguard matches Codeberg.
- Thawguard cannot decrypt a stored webhook secret or status token: restore the original `THAWGUARD_SECRET_KEY` or recreate the local database volume.
- Inspecting the live SQLite database requires copying the WAL files too: copy `/data/thawguard.db`, `/data/thawguard.db-wal`, and `/data/thawguard.db-shm` to the same local directory before opening the database.
- Docker cannot reach the app on non-Linux hosts: run `go run ./cmd/thawguard` locally for now. The compose file intentionally uses Linux host networking to preserve loopback-only bootstrap safety.

## What Alpha A does not do

- It does not post commit statuses in the default dry-run configuration.
- It does not enable `THAWGUARD_STATUS_PUBLISHER=forgejo_status` unless the explicit live-pilot opt-in and repository allowlist are set.
- It does not configure Codeberg branch protection.
- It does not require Codeberg API tokens for shadow mode. Stored status tokens are encrypted setup data for future live posting.
- It does not provide production-ready local user authentication.
