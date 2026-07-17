# Local Forgejo integration and E2E

This runbook provides two Linux-hosted development modes:

- a persistent manual stack for interactive Thawguard and Forgejo work; and
- a disposable automated smoke test that provisions a real local Forgejo repository and exercises actual signed webhook delivery, status posting, and branch protection.

Thawguard is cooperative enforcement for trusted teams. These checks demonstrate accidental-merge prevention and auditable workflow behavior. They do not make Thawguard an unbypassable security boundary against forge users who can post statuses with sufficient permissions.

## Requirements and network boundary

Install Docker with Docker Compose, Go, and OpenSSL. The Compose files are Linux-oriented because both services use host networking while binding only to the host loopback interface:

- Thawguard: <http://127.0.0.1:8080>
- Forgejo: <http://127.0.0.1:3000>

Neither service binds to `0.0.0.0`, and no SSH port is enabled. Forgejo can deliver directly to Thawguard at `127.0.0.1` without a tunnel because both containers share the Linux host network namespace.

Manual and automated modes intentionally share ports. Stop the other stack or process first if either port is occupied.

The local overlay pins:

```text
codeberg.org/forgejo/forgejo:15.0.4@sha256:9e14382433760127c87cb78c4dbc44b45abbb0c09c8479812c8e99b3dc893429
```

## Persistent manual mode

### 1. Create the local Thawguard installation key

Create an ignored `.env` file from the repository root. Keep this key stable while retaining the local Thawguard volume; changing it makes stored webhook secrets and status tokens undecryptable.

```sh
umask 077
THAWGUARD_SECRET_KEY=$(openssl rand -base64 32)
cat > .env <<EOF
THAWGUARD_SECRET_KEY=$THAWGUARD_SECRET_KEY
THAWGUARD_PUBLIC_URL=http://127.0.0.1:8080
EOF
unset THAWGUARD_SECRET_KEY
```

Do not commit `.env`, tokens, webhook secrets, or local database files.

### 2. Start both services

```sh
make local-up
```

The command builds Thawguard, starts the persistent `thawguard-local` Compose project, and waits for both HTTP health checks.

### 3. Create the first local Forgejo administrator

Use a fictional local identity. Ask Forgejo to generate the initial password so it never appears in the command arguments:

```sh
docker compose --project-name thawguard-local \
  --file compose.yaml --file compose.local.yaml \
  exec --no-TTY --user git forgejo \
  forgejo --work-path /data/gitea --config /data/gitea/conf/app.ini \
  admin user create \
  --username local-admin \
  --random-password \
  --random-password-length 24 \
  --email local-admin@thawguard.test \
  --admin
```

Forgejo prints the generated password once. Copy it from the terminal, log in at <http://127.0.0.1:3000>, and change it when Forgejo prompts you. Create only fictional local users and repositories.

### 4. Prepare a Forgejo repository

In Forgejo:

1. Create a fictional repository and initialize its `main` branch.
2. Create a feature branch with at least one commit.
3. Create an access token for the fictional repository owner with repository read/write access. Keep it local and paste it directly into Thawguard when needed.
4. Protect `main`, enable required status checks, and require the exact context `thawguard/freeze`. Apply the rule to repository administrators if the repository owner will perform the merge-blocking check.

### 5. Configure Thawguard and the webhook

1. Open <http://127.0.0.1:8080/setup> and create the first local Thawguard admin.
2. On `/repositories`, connect the Forgejo repository using base URL `http://127.0.0.1:3000`.
3. Store a locally generated webhook secret and the fictional owner's Forgejo access token in the write-only encrypted forms.
4. Add any additional exact managed branches before activation. The default branch is managed automatically.
5. In Forgejo, add an active repository webhook:
   - target: `http://127.0.0.1:8080/webhooks/forgejo`
   - content type: JSON
   - secret: the same locally generated value stored in Thawguard
   - event: pull requests
6. Open a real pull request into `main`. Forgejo should deliver the signed event to Thawguard.
7. Confirm the verified, processed delivery on `/webhooks`.
8. Run read-only readiness checks on `/repositories`. Every mandatory check must pass for every exact managed branch before status verification becomes available.
9. Correct any reported branch protection or required-context failure in Forgejo, rerun readiness, then use **Verify status posting** and **Activate enforcement**. Thawguard reports the required setup but does not configure Forgejo branch protection automatically.

### 6. Exercise the freeze lifecycle

1. Create a freeze for `main` on `/freezes`.
2. Confirm Forgejo records `thawguard/freeze=failure` on the pull request head.
3. Confirm the protected branch refuses a normal merge because the required status is failing.
4. Lift the freeze through Thawguard.
5. Confirm the same status context becomes `success`.

Thawguard posts only its own status context. It does not replace other required checks or prevent a sufficiently privileged collaborator from bypassing cooperative policy.

### 7. Stop, restart, reset, and inspect

```sh
make local-logs   # follow both services
make local-down   # stop containers; retain both named volumes
make local-up     # restart with retained Forgejo and Thawguard state
make local-reset  # delete both named volumes and start a fresh stack
```

Use `local-reset` only when the stored Forgejo repositories, users, and Thawguard database can be discarded. A normal `local-down` followed by `local-up` preserves both services' data.

## Disposable automated E2E

Run the narrow local smoke with:

```sh
make e2e
```

The target:

1. uses the separate `thawguard-e2e` Compose project;
2. removes any old disposable containers and volumes;
3. generates all passwords, secrets, the Thawguard installation key, and three distinct Forgejo tokens in memory;
4. starts fresh Forgejo and Thawguard containers and waits for both health checks;
5. creates a local Forgejo admin and fictional repository owner through the Forgejo admin CLI;
6. uses a control token to provision and inspect a private repository, branches, commits, branch protection, and webhook through Forgejo's HTTP API, initially protecting only `main` and deliberately leaving the managed `release` branch unprotected;
7. creates the first Thawguard admin and stores a separate primary status token, webhook secret, and managed branches through real CSRF-protected HTTP forms;
8. opens a real Forgejo pull request, causing Forgejo itself to emit the signed webhook;
9. verifies the real delivery, runs the CSRF-protected readiness check, and proves the `release` branch row reports readable protection evidence but fails protection enabled, required status checks, and the exact `thawguard/freeze` context while the repository remains setup-incomplete and verification and activation stay unavailable;
10. adds the missing exact `release` protection through Forgejo's API, validates Forgejo's creation response, and proves all four branch checks pass;
11. completes status-post verification and activates enforcement through the normal workflow only after every mandatory check passes across both managed branches;
12. creates a freeze and observes a failing status;
13. confirms the required status blocks the merge;
14. captures the authenticated session CSRF token, active freeze identity and fields, latest failing required-status ID, webhook count, publication-attempt count, and existing freeze history; deletes only the exact `release` protection; then submits the real CSRF-protected reconciliation form and proves failed readiness marks enforcement unhealthy, leaves automatic recovery pending, and synchronizes or publishes nothing;
15. stops only the Thawguard service through a fixed `docker compose ... stop thawguard` argument vector, leaving Forgejo, the pull request, tokens, and both volumes in place; while Thawguard is stopped, restores the exact `release` protection and uses the fictional control token to post a deliberate `thawguard/freeze=success` drift fixture;
16. starts only Thawguard, polls HTTP readiness, and proves the same browser remains authenticated with the same CSRF token while the repository, encrypted credential markers, active freeze ID, branch, reason, state, and prior history remain visible;
17. proves the restarted reconciliation worker consumes the existing durable recovery work without a manual recovery request, reruns repaired readiness checks, returns enforcement to active, records a successful **Enforcement recovery** by **Reconciliation runner** with one PR evaluated, one required status posted, and zero failures, adds exactly one publication attempt, and leaves the webhook-row count unchanged;
18. proves strict Forgejo status ordering from the old Thawguard failure to the injected fictional success to the recovered Thawguard failure, then confirms the ordinary merge is blocked again;
19. revokes only the primary status token through Forgejo's supported access-token API, addressed by its non-secret token name and authenticated with the owner's CLI-generated random password because pinned Forgejo rejects token authentication on this endpoint;
20. advances the existing feature branch with the control token so Forgejo emits a real synchronized-pull-request webhook for a new head SHA;
21. proves that no `thawguard/freeze` status reaches the new head, the missing required status blocks the merge, the delivery records only generic retryable-failure diagnostics, and Thawguard records sanitized publication and runtime-convergence failure evidence while becoming unhealthy;
22. rotates to the pre-generated replacement status token through Thawguard's real CSRF-protected form and immediately requests manual recovery, while tolerating a harmless race with the automatic worker;
23. proves recovery returns enforcement to active, keeps the historical failed publication visible without credentials, republishes `thawguard/freeze=failure` on the new head, and leaves the frozen merge blocked;
24. records the open-PR sync baseline, then sends sanitized in-memory E2E fixtures to prove an invalid signature has no trusted side effects and one valid repository-scoped delivery ID cannot process or publish twice;
25. lifts the first freeze, observes `thawguard/freeze=success` on the new head, and completes the existing open-PR sync and cache proof;
26. creates a second active freeze with a distinct fictional reason, captures its rendered identity and pre-cancel webhook, publication, status, and activity baselines, observes `thawguard/freeze=failure`, and confirms the required status blocks a normal merge;
27. cancels that exact active freeze through the authenticated CSRF-protected form, proves the newest **Branch freeze** activity is **Cancelled** rather than **Lifted**, and observes `thawguard/freeze=success` with no new webhook row or publication intent, exactly one new publication attempt, and exactly one new Forgejo required-context status;
28. creates a third active `main` freeze for the fictional per-PR thaw verification, captures its rendered identity, branch, reason, and active state, waits for the failing status and posted publication attempt, and confirms the ordinary merge remains blocked;
29. submits the real authenticated CSRF-protected thaw form for the existing uniquely headed PR without a `head_sha` field, proving Thawguard fetches the current head directly from Forgejo and synchronizes exactly one real open PR instead of requesting shared-head confirmation;
30. proves the newest isolated decision result and **Single-PR thaw** activity identify the repository, real PR, current head, target branch, approver, and fictional reason; observes `thawguard/freeze=success` with the explicit-thaw description, no new webhook row or publication intent, exactly one new status result, publication attempt, and Forgejo required-context status, and exactly two new activity events for the sync and approval;
31. proves the third branch freeze remains unchanged and active while the PR receives the passing exception status, then captures the old thawed SHA's complete required-context status history, newest **Eligible** decision, newest **Single-PR thaw** activity, exact active-freeze evidence, and rendered webhook, status-result, publication, and activity counters;
32. confirms the real PR still has that exact thawed head, creates the allowlisted `stale-head-thaw.txt` fixture through Forgejo's contents API with the control token, requires a distinct new SHA, and waits for the real PR head to advance;
33. proves Forgejo emits exactly one new real `pull_request/synchronized` delivery that is verified, processed, and error-free; proves the synchronized reevaluation produces exactly one new-SHA `thawguard/freeze=failure` status and one posted attempt with the normal frozen-branch description; and confirms the ordinary merge is blocked again;
34. proves the synchronized reevaluation adds exactly one webhook row, status result, desired-status intent, publication attempt, and new-head Forgejo status while adding no activity event; separately re-fetches the old SHA and proves its status history, latest explicit-thaw success, **Eligible** decision, and **Single-PR thaw** evidence remain unchanged;
35. proves the newest blocked decision, publication intent, and posted attempt identify the repository, real PR, new full SHA, `main`, `thawguard/freeze`, and frozen-branch result; proves the exact third freeze remains unchanged and active; and retains the open PR at its new blocked head, with no matching exception for that head;
36. creates the static `shared-head-confirmation` branch from `feature/freeze-check` through Forgejo's branch API, validates its returned commit ID exactly matches the first PR's current blocked SHA, and opens a distinct real second PR targeting `main` at that same full SHA;
37. waits for exactly one new real, verified, processed, error-free `pull_request/opened` delivery and proves it adds one status result, one publication attempt, and one failing Forgejo required-context status while reusing the existing SHA-scoped publication intent and adding no activity event; both ordinary merge attempts remain blocked;
38. submits the ordinary thaw fields for the first PR with no client-supplied head or affected set, receives `409 Conflict`, and verifies the isolated confirmation warning names both real PRs, their distinct titles, `main`, the shared short SHA, the selected PR, and the explicit statement that nothing has been approved yet;
39. proves the initial request performs only the intentional audited two-open-PR refresh: it adds no webhook, status result, publication intent, publication attempt, Forgejo status, shared-thaw audit, or success decision, while the active freeze and latest failure remain unchanged;
40. validates the confirmation form's original request values, full current SHA, and opaque 64-character affected-set fingerprint; submits only those extracted values through the existing forge refresh and staleness recheck instead of trusting client-supplied PR metadata;
41. proves explicit confirmation atomically records new current-SHA exceptions for both frozen PRs, records one **Shared-head thaw** approval naming both PRs and the exact fictional reason, and publishes one shared `thawguard/freeze=success` status while both PRs remain open at the same SHA and the active freeze remains unchanged;
42. checks all three token values against rendered diagnostic pages, relevant HTTP responses and redirects, Forgejo status API responses, captured Go test output, and both container logs without printing unsafe content; and
43. removes both containers and both named volumes on success or failure.

The initial pull request and both later feature-branch advance deliveries are Forgejo-emitted. The status drift is a deliberate cooperative-enforcement fixture posted with the disposable fictional control token while Thawguard is stopped; the test does not attempt a merge while that success is newest. The rejection and duplicate probes are clearly identified synthetic E2E fixtures; they run only after credential recovery, reuse the fictional repository, and never store or print their payloads, signatures, or in-memory secret. Separate status tokens keep fixture control independent from the credential under failure, but all three tokens belong only to the disposable fictional owner.

The second lifecycle cancels an already-active freeze. Active **Cancel** records the distinct **Cancelled** outcome and republishes current policy; **Lift** records **Lifted**, while scheduled cancellation applies only to a future window that has not activated. The test does not merge after the passing status because the updated required context is sufficient proof that Thawguard removed its cooperative merge block.

The third lifecycle approves an immediate thaw for one uniquely headed PR while its branch freeze remains active. The submitted form identifies the repository, PR, target branch, and reason but does not submit a head SHA; Thawguard fetches the current head from Forgejo, records the exact-head exception, and publishes the passing status.

The synchronized-head lifecycle then advances that real PR to different code. The old exact-head approval no longer applies to the changed head, so the still-active branch freeze produces the normal failing status again. The old exception row is retained as active for its old SHA rather than expired, revoked, or permanently invalidated; returning the PR to that exact old SHA could make the approval applicable again. No invalidation audit event is invented. The retained new blocked head and unchanged active freeze prepare the same disposable fixture for shared-head confirmation coverage without implying hard enforcement against forge writers who can post statuses.

The shared-head lifecycle creates a second real open PR at that retained blocked SHA. The first ordinary thaw request returns a truthful `409 Conflict` after an audited refresh reports two open PRs, but it records no approval and publishes no status. The follow-up form carries the full server-observed SHA and an opaque affected-set fingerprint used only by the server's staleness recheck; it does not submit an affected-PR list or mutable metadata for those PRs. This smoke round-trips the untouched server-rendered values, while lower-level tests cover reconfirmation after a changed head or affected set. Explicit confirmation refreshes the forge state again, atomically approves both currently frozen PRs, records one shared audit event, and publishes one SHA-scoped success. Both PRs remain open and the branch freeze remains active, so this remains cooperative workflow evidence rather than a claim of hard enforcement against forge writers.

The restart proof covers persisted unhealthy state and already-enqueued recovery work. The restarted worker consumes that existing job when it becomes due; startup does not enqueue or reconcile every otherwise healthy active repository. This is not a universal startup sweep.

This is a cooperative-enforcement recovery proof for trusted teams. It demonstrates that a missing required status prevents an ordinary merge and that operators can rotate credentials and converge current policy through audited workflows. A forge collaborator with sufficient permission to post statuses remains outside Thawguard's security boundary.

The Go test has an `e2e` build tag and also requires `THAWGUARD_E2E=1`. Ordinary commands remain Docker-free:

```sh
go test ./...
```

For debugging a failed run only:

```sh
make e2e-keep
```

That target leaves a failed `thawguard-e2e` project running and prints the exact cleanup command. Successful runs are always removed. Go test output is captured and scanned before it is printed; container logs are scanned before cleanup but are never dumped by the runner. If a generated credential or secret is detected, the runner prints only the affected surface label and withholds the unsafe content.

Maintainers can verify the failure trap without provisioning fixtures:

```sh
E2E_FAIL_AFTER_START=1 bash scripts/e2e.sh
E2E_FAIL_AFTER_START=1 make e2e
```

The script intentionally exits with status 97 after both services become healthy. When invoked directly, `bash scripts/e2e.sh` exits exactly 97. Through `make e2e`, GNU Make reports the failed recipe as `Error 97` and normally exits 2. Both entry points must still remove the disposable containers and volumes.

## Prioritized E2E expansion matrix

The disposable smoke covers the freeze/lift, active-cancel, immediate unique-head thaw, synchronized stale-head reevaluation, and shared-head confirmation paths plus the setup-readiness, webhook, and token-failure P0 rows below. Add the remaining cases in this order:

| Priority | Scenario | Main proof |
| --- | --- | --- |
| P0 (covered) | Invalid webhook signature and duplicate delivery | Invalid input has no side effects; a repository-scoped duplicate is idempotent. |
| P0 (covered) | Token failure and redaction | Posting fails closed, recovery evidence is sanitized, and no token reaches output. |
| P0 (covered) | Setup readiness failure and recovery | An unprotected managed branch blocks verification and activation; adding the missing Forgejo protection allows the normal workflow to proceed. |
| P0 (covered) | Restart persistence and reconciliation | A Thawguard-only restart preserves durable state and an existing recovery job converges current frozen policy without implying a universal startup sweep. |
| P1 (covered) | Cancel freeze | Active cancellation records **Cancelled**, reuses the desired-status intent, republishes current policy, and remains distinct from Lift and scheduled cancellation. |
| P1 (covered) | Immediate per-PR thaw | A real PR/head receives an audited exception and success status while its branch remains actively frozen. |
| P1 (covered) | Stale-head thaw reevaluation | A changed head no longer matches the retained old exact-head approval and is blocked again by the still-active freeze. |
| P1 (covered) | Shared-head confirmation | SHA-scoped impact is shown, the initial request makes no approval/publication mutation, and explicit confirmation atomically covers the refreshed affected set. |
| P2 | Scheduled create/edit/Start Now/cancel | One-time schedule transitions use the normal convergence path. |
| P2 | Planned unfreeze | Due unfreeze republishes success and survives restart. |
| P2 | Viewer/freezer/thaw-approver/admin permissions | Real sessions enforce each route and action boundary. |
| P3 | Audit and activity evidence | Operator-visible records contain required evidence without raw secrets or payloads. |

Do not expand the first smoke into a generic provider framework. Each case should reuse the existing Forgejo and Thawguard HTTP surfaces.

## Future optional real-Codeberg smoke

A real-Codeberg profile is design-only and requires separate approval before implementation or execution. It should:

- use a stable public HTTPS tunnel restricted to `POST /webhooks/forgejo` where practical;
- use a throwaway Codeberg repository and short-lived, least-privilege credentials;
- require explicit credential-gating and never run from `go test ./...`, normal `make e2e`, or CI;
- verify one real webhook delivery and one real status-posting lifecycle;
- avoid committing or printing credentials, raw payloads, signatures, or tunnel configuration; and
- tear down the tunnel and throwaway test state after the smoke.

No tunnel provider is selected, installed, or represented in the current Compose files.

## Troubleshooting

- **Port already in use:** stop the persistent stack with `make local-down` before `make e2e`, or stop the unrelated loopback process.
- **Forgejo webhook is not delivered:** confirm the target is `http://127.0.0.1:8080/webhooks/forgejo`, the event is pull requests, and both services are in the same host-networked Compose stack.
- **Readiness fails:** confirm the encrypted status token can read pull requests and branch protection, every managed branch is protected, and each requires the exact `thawguard/freeze` context.
- **Secret or token cannot be decrypted:** restore the original `THAWGUARD_SECRET_KEY` for that Thawguard volume or intentionally reset the local stack.
- **Inspecting SQLite manually:** copy `thawguard.db`, `thawguard.db-wal`, and `thawguard.db-shm` together before opening the database. Never publish the copied database.
