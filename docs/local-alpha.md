# Local alpha E2E runbook

This runbook starts Thawguard locally with Docker and exercises repository setup and signed Forgejo/Codeberg pull-request webhooks against throwaway repositories.

Alpha scope:

- Thawguard has one operational mode: an enforcement-active repository synchronizes current open PRs from the forge and posts real `thawguard/freeze` commit statuses.
- Repository enforcement activation is explicit. Read-only readiness checks verify the encrypted status token, pull-request access, every managed branch's protection and exact required context, and recent signed webhook evidence. Activation reruns readiness, performs a controlled `thawguard/setup` status post, synchronizes current open pull requests, and publishes current policy before changing the repository to active.
- A setup-incomplete repository can be fully configured: credentials can be stored, and signed webhooks are verified and recorded as setup evidence. It cannot create freezes, schedules, or thaws, and no commit status is posted for it.
- Thawguard is cooperative enforcement for trusted teams and is not a hard security boundary.

## 1. Generate a local secret key

Create a local `.env` file. It is ignored by git.

```sh
THAWGUARD_SECRET_KEY=$(openssl rand -base64 32)
cat > .env <<EOF
THAWGUARD_SECRET_KEY=$THAWGUARD_SECRET_KEY
THAWGUARD_PUBLIC_URL=http://127.0.0.1:8080
EOF
```

Keep this key stable for a local alpha database. If it changes, stored webhook secrets and status-posting tokens become undecryptable.

## 2. Start the local Docker alpha

```sh
docker compose up --build
```

Open <http://127.0.0.1:8080> and create the first local admin user if this is a fresh database. The first account starts with all MVP roles so the local bootstrap user can configure repositories.

Thawguard runtime configuration is environment-variable based. The Docker Compose file sets `THAWGUARD_DB_PATH=/data/thawguard.db`; the binary does not parse `--db` or `--addr` CLI flags.

The compose file is Linux-oriented. It uses host networking so first-admin setup can stay on `127.0.0.1:8080`. Host networking has lower network isolation than the default Docker bridge, so treat this as a local-alpha convenience only. Do not change the container to bind `0.0.0.0` before the first local admin user exists.

The first build may pull Docker base images and Go modules. This runbook does not publish images or contact Codeberg during the Docker build.

For the repeatable E2E loop, export a stable local key in your shell or keep it in `.env`. The Makefile loads `.env` for these targets, matching Docker Compose's behavior. Then use:

```sh
make e2e-up      # build/start without deleting state
make e2e-reset   # delete the Docker volume, rebuild, and start fresh
make e2e-down    # stop without deleting state
make e2e-logs    # follow Thawguard logs
```

`make e2e-reset` deletes the `thawguard-data` Docker volume. Use it when you want a clean E2E database and are ready to re-enter repository setup, webhook secret, and status token.

Local alpha data is stored in SQLite and includes append-only operator metadata such as audit events, status decisions, status publication attempts, and webhook delivery receipts. The logical database should stay small during E2E testing, but the SQLite WAL file can be larger until checkpointed; this is normal SQLite behavior. Use `make e2e-reset` for clean test runs. Production retention, deletion, and export policy are not yet wired.

To stop without deleting local state:

```sh
docker compose down
```

To delete the local alpha database volume:

```sh
docker compose down -v
```

## 3. Configure a throwaway repository in Thawguard

Use a throwaway Forgejo/Codeberg repository, not a production repository.

1. Go to `/repositories`.
2. Add the throwaway repository:
   - Forge: `forgejo`
   - Base URL: `https://codeberg.org`
   - Owner: your mock owner or organization
   - Repository: your mock repository name
   - Default branch: usually `main`
3. Set a webhook secret. Use a high-entropy value and save it somewhere local temporarily.
4. Set a status token with enough forge permission to post commit statuses and read pull requests for the throwaway repository. It is stored encrypted and is required before enforcement can ever be activated.

The repository card shows its enforcement state. New repositories are setup-incomplete after read-only readiness checks until an administrator explicitly activates enforcement and the controlled status-post plus initial policy convergence succeed.

The card also lists the repository's managed branches — the exact branch names freezes and scheduled freezes may target. The default branch is always managed and cannot be removed. Admins can add or remove exact branch names (no globs or patterns) while enforcement is inactive; a branch with an active or pending scheduled freeze cannot be removed. An administrator can run read-only readiness checks for all managed branches from the card.

## 4. Connect Forgejo/Codeberg webhooks safely

Codeberg must reach `POST /webhooks/forgejo` to send real webhooks. For local testing, use a tunnel or reverse proxy you trust, with HTTPS/TLS enabled.

Important safety rule: local Thawguard users are for trusted operators. Admin, freezer, thaw approver, and viewer are explicit local role flags, not a hard security boundary against forge write collaborators. Do not expose the full Thawguard UI to the public internet during alpha testing. Prefer a tunnel/proxy that only forwards:

```text
POST /webhooks/forgejo
```

Configure the webhook on the throwaway repository:

- Payload URL: `<your-public-webhook-url>/webhooks/forgejo`
- Secret: the same webhook secret saved in Thawguard
- Event: pull requests

If your tunnel cannot restrict paths, use a throwaway repository and an ephemeral tunnel URL, keep the test short, and stop the tunnel immediately after the test.

## 5. Setup-incomplete E2E flow

In the throwaway Forgejo/Codeberg repository:

1. Create a branch.
2. Open a pull request into `main`.
3. Push another commit to the PR branch.

In Thawguard, inspect:

- `/activity` — the primary recent chronological audit history should show curated operator and system changes, affected targets, outcomes, and timestamps.
- `/webhooks` — secondary signed-delivery diagnostics should show receipts as verified and processed with sanitized delivery metadata.
- `/repositories` — the repository card shows setup-incomplete enforcement plus configured credentials.
- `/repositories` — run readiness checks to read the open-PR endpoint and each exact managed branch's protection. The card also shows whether a verified `pull_request` delivery was received in the last 24 hours. Then use explicit activation when every prerequisite is ready.
- `/freezes`, `/scheduled-freezes`, `/decisions` — mutation forms are unavailable and explain that enforcement must be activated first. Server-side validation rejects these actions as well.
- `/publications` — secondary status diagnostics should contain no publication intents or attempts for a setup-incomplete repository.

These pages render sanitized metadata only. Raw webhook payloads, signatures, request headers, webhook secrets, status tokens, passwords and hashes, raw forge response bodies, and session IDs are not displayed. Retention and export remain deferred.

Codeberg will not show a Thawguard commit status for a setup-incomplete repository.

## 6. Enforcement-active behavior

Once a repository is enforcement-active, every freeze lifecycle action follows one invariant:

1. Freeze create, lift/end, cancel, scheduled activation, and planned unfreeze first synchronize current open PRs from the forge using the repository's encrypted status token.
2. Thawguard evaluates each affected head SHA across the whole repository. A commit status applies to the commit, so open PRs on other target branches sharing the same head are part of the same decision; a shared SHA cannot show success unless every affected frozen PR is covered.
3. Thawguard posts only the `thawguard/freeze` status context and records each posted or failed attempt.

Thaw approval fetches the selected PR's current head SHA from the forge, stores the exception for that exact head, recomputes the shared-head status, and publishes the result. If several open PRs share the head SHA, Thawguard pauses for explicit confirmation before approving all of them. A missing status token or a forge failure fails closed: no status is posted, and failures during posting are recorded as sanitized failed attempts.

If a policy change commits but live convergence fails, Thawguard marks the repository unhealthy and retains one durable automatic recovery job. Recovery retries the complete current repository state after restart as well as during the running process; the existing admin retry action uses the same proof and job.

Scheduled freeze windows activate from the local Thawguard process. Admins and Freezers can edit a pending schedule's reason, future start time, and optional planned unfreeze without changing its repository or branch. Clearing the optional value removes the planned unfreeze. **Start Now** activates a still-pending future schedule immediately, preserves a future planned unfreeze exactly, and runs the same current-forge synchronization, repository-wide shared-head evaluation, publication, durable intent, and retry path as automatic activation. If live convergence fails after activation commits, the schedule remains active while repository enforcement becomes unhealthy and one reconciliation job retries with bounded backoff.

Only pending schedules are editable or startable. A planned unfreeze that is no longer in the future must be edited before Start Now. Recurring schedules and archive controls remain deferred. Keep the process running for scheduled starts, retries, and planned unfreezes to execute.

## Troubleshooting

- No delivery row on `/webhooks`: check the public webhook URL, event type, and whether the tunnel is forwarding `POST /webhooks/forgejo`.
- Delivery row with an error: check repository owner/name/base URL and whether the webhook secret in Thawguard matches Codeberg.
- Thawguard cannot decrypt a stored webhook secret or status token: restore the original `THAWGUARD_SECRET_KEY` or recreate the local database volume.
- Freeze/schedule/thaw forms are unavailable: the repository's enforcement is not active. Complete readiness and use the explicit activation control on `/repositories`.
- Inspecting the live SQLite database requires copying the WAL files too: copy `/data/thawguard.db`, `/data/thawguard.db-wal`, and `/data/thawguard.db-shm` to the same local directory before opening the database.
- Docker cannot reach the app on non-Linux hosts: run `go run ./cmd/thawguard` locally for now. The compose file intentionally uses Linux host networking so first-admin setup stays loopback-only until a local user exists.

## What this local alpha does not do

- It does not post commit statuses for setup-incomplete repositories, and it has no shadow/dry-run runtime mode.
- It does not provide recurring schedules or schedule archive controls.
- It does not configure Codeberg branch protection.
- It does not provide production-ready local user authentication.
