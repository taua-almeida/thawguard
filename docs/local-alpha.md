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

`THAWGUARD_PUBLIC_URL` is Thawguard's canonical browser origin and the origin used for generated recovery links. Configure a root-only HTTPS URL with no credentials, query, or fragment. HTTP is accepted only for exact `localhost` or a literal loopback IP, as in the local value above. Internationalized and punycode (`xn--`) hostnames are currently unsupported; use an ordinary ASCII hostname.

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
3. On `/users`, open the first Admin's detail page and grant that account **Freezer** for the connected repository. Add **Thaw approver** too if you will exercise thaw requests. Admin alone manages installation setup and view-all access; it does not imply either repository action role.
4. Store a locally generated webhook secret and the fictional owner's Forgejo access token in the write-only encrypted forms.
5. Add any additional exact managed branches before activation. The default branch is managed automatically.
6. In Forgejo, add an active repository webhook:
   - target: `http://127.0.0.1:8080/webhooks/forgejo`
   - content type: JSON
   - secret: the same locally generated value stored in Thawguard
   - event: pull requests
7. Open a real pull request into `main`. Forgejo should deliver the signed event to Thawguard.
8. Confirm the verified, processed delivery on `/webhooks`.
9. Run read-only readiness checks on `/repositories`. Every mandatory check must pass for every exact managed branch before status verification becomes available.
10. Correct any reported branch protection or required-context failure in Forgejo, rerun readiness, then use **Verify status posting** and **Activate enforcement**. Thawguard reports the required setup but does not configure Forgejo branch protection automatically.

Admins can also open another enabled user's detail page in **Users & Access**, issue a one-hour manual recovery link, and share it through a trusted channel. Thawguard displays the bearer link once and stores only its digest. This local-alpha slice does not send email or expose a public forgot-password request form.

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
42. creates the static `scheduled-transition` branch from `release`, adds the fictional `scheduled-transition.txt` fixture through Forgejo's contents API, requires its new full SHA to differ from both the `release` base and shared `main` head, and opens a third real PR targeting the protected `release` branch;
43. waits for exactly one verified, processed, error-free `pull_request/opened` delivery and proves it adds one status result, desired-status intent, posted attempt, and Forgejo `thawguard/freeze=success` status with the no-active-freeze description while adding no activity event and leaving the full shared-`main` status history unchanged;
44. creates two independent one-time `release` schedules through the real CSRF-protected form, identifies each by its exact ID and unique fictional reason, and proves each creation adds only one **Freeze schedule / Scheduled** activity event with its actor and times;
45. cancels the exact still-pending Schedule B through `/scheduled-freezes/cancel`, proves its cancelled timestamp and **Freeze schedule / Cancelled** audit evidence, removes its pending Edit, Start Now, and Cancel controls, and leaves Schedule A and all webhook/status/publication evidence unchanged;
46. edits the exact Schedule A ID through `/scheduled-freezes/edit` using second-precision RFC3339 UTC values approximately 60 and 90 seconds ahead, proves the repository and `release` target stay fixed, and verifies the rendered reason, times, controls, and truthful before/after **Changed** activity without publication side effects;
47. submits Schedule A's **Start Now** before its edited start, then proves normal convergence adds no webhook, one status result, no new desired-status intent, one posted attempt, one failing Forgejo status, and exactly two activity events: **Scheduled freeze Start Now / Started** by **E2E Admin** and an open-PR sync reporting three open PRs and zero cached PRs closed;
48. proves Schedule A keeps its ID, edited reason, and planned-unfreeze time while becoming the active `release` freeze, the required status blocks the release PR's ordinary merge, the original active `main` freeze and complete shared-head status history remain unchanged, Schedule B remains cancelled history, and no pending schedule remains;
49. captures the retained active Schedule A ID, edited reason, actual Start Now time, precise planned end, active `release` freeze, cancelled Schedule B row, open release PR and full head SHA, complete release and shared-`main` status histories, active `main` freeze, historical single-PR thaw evidence, authenticated CSRF token, repository health, and all webhook/status/publication/activity counters; requires at least 50 seconds before the planned end and at least 120 seconds of test context after it before any stop;
50. stops only Thawguard through the same fixed `docker compose ... stop thawguard` argument vector before Schedule A is due, keeps Forgejo and both volumes online, and proves the release PR remains open at the same full SHA with unchanged status history;
51. waits with a context-bound timer until one second after the persisted planned end while Thawguard remains down, then proves Forgejo is still available and the release PR and status history are still unchanged without calling a Thawguard route during downtime;
52. starts only Thawguard, uses `/healthz` only as the observation gate, and proves the existing browser session remains authenticated with the exact same CSRF token before the startup lifecycle pass converges the overdue persisted row;
53. proves startup execution adds zero webhooks, one status result, zero desired-status intents, one posted `forgejo_status` attempt, one Forgejo `thawguard/freeze=success` status with `No active freeze applies to this PR`, and exactly two activity rows; the desired-status row is reused from failure to success and the new Forgejo status ID follows Schedule A's failure;
54. proves exactly one **Scheduled planned unfreeze / Completed** activity by **Scheduler** retains the edited reason and planned end, and exactly one successful open-PR sync truthfully retains its current **Unknown system actor** label and reports `3 open PRs synchronized; 0 cached PRs marked closed`; Schedule A becomes completed with its branch, reason, start, planned end, and ended time retained, Schedule B remains unchanged cancelled history, and active freezes move from two to the unchanged `main` freeze only;
55. waits one additional lifecycle interval and requires no webhook, status-result, desired-intent, publication-attempt, Forgejo-status, activity, schedule-row, or active-freeze change, guarding against duplicate startup or periodic work;
56. as a separate terminal phase, submits the ordinary merge for only the now-eligible `release` PR, tolerates only temporary required-check `405` responses while Forgejo converges mergeability, requires the PR to become closed and merged, and proves exactly one real verified, processed, error-free `pull_request/closed` webhook with no status, publication, Forgejo-status, or activity side effect; both `main` PRs, the shared-head history, historical thaw evidence, repository health, and schedule/freeze history remain unchanged;
57. grants the bootstrap Admin explicit Viewer, Freezer, and Thaw-approver access to the primary repository, adds a second setup-only repository as a visibility boundary, and uses the real **Users & Access** flow to create zero-access **E2E Admin Only**, **E2E Freezer**, and **E2E Thaw Approver** accounts; each grant is saved separately, every new account replaces its temporary password through the forced-change flow, and Admin-only creates and grants **E2E Viewer** through the same surfaces;
58. proves every scoped session receives HTTP 200 for the dashboard, repositories, active freezes, scheduled freezes, thaw requests, activity, status diagnostics, and webhook diagnostics while seeing only the granted primary repository; Admin-only can also see the ungranted boundary repository and receives HTTP 200 for `/users`, while Freezer, Thaw approver, and Viewer receive exact HTTP 403 responses and never see **Users & Access** navigation;
59. verifies rendered controls match the repository-scoped contract: Admin-only manages repositories, users, and access but receives no Freeze, schedule, or Thaw actions; Freezer receives active-freeze and full schedule controls only for the granted repository; Thaw approver receives only its thaw mutation form; Viewer receives read-only surfaces only;
60. sends valid-Origin, valid-session-CSRF, otherwise mutation-capable wrong-role forms for every admin-only repository route (repository creation, managed-branch add/remove, webhook-secret and status-token rotation, readiness check, status verification, activation, deactivation, reconciliation, and recovery) and every admin-only user-detail route (Admin access, repository-access save/remove, disable, enable, and password-recovery issuance), plus active-freeze create/end/cancel, scheduled create/edit/Start Now/cancel, and thaw approval; every request requires exact HTTP 403, while full stable admin `/users` and `/repositories` snapshots plus user/repository/freeze/schedule, webhook, status-result, desired-intent, publication-attempt, activity, session, and Forgejo-status evidence prove no denied mutation or recovery issuance occurred;
61. has **E2E Freezer** create, edit, and use **Start Now** on future fictional Schedule C on `release`, and proves all three activity rows carry that repository-scoped actor while completed Schedule A and cancelled Schedule B remain unchanged;
62. proves Schedule C activation against the already-merged release fixture adds no release status result, desired intent, publication attempt, or Forgejo status and does not reopen the release PR; both open `main` PRs, their shared head, the active `main` freeze, and their prior status history remain intact during the schedule actions;
63. requires Admin-only's valid-CSRF attempt to cancel the resulting active `release` freeze to return exact HTTP 403, then has **E2E Freezer** cancel that exact active freeze through `/freezes/cancel`; Schedule C becomes cancelled, the cancellation activity names E2E Freezer, and no release or shared-`main` status is published;
64. advances only the existing primary `feature/freeze-check` PR with the sanitized `role-boundary-thaw.txt` fixture, requires exactly one real verified and processed `pull_request/synchronized` webhook, and observes the normal frozen-branch failure on its new unique full SHA; the secondary PR stays open at the old shared SHA, all prior shared-head statuses remain an unchanged prefix, and the existing previous-head invariant appends exactly one success recomputation for that still-open thawed PR;
65. submits the same valid-CSRF, no-client-head thaw request as Admin-only, Freezer, and Viewer, requires exact HTTP 403 with no mutation, then has **E2E Thaw Approver** approve the unique current head through the real form; the approval adds one expected result, reused desired intent, posted attempt, Forgejo success, and exact E2E Thaw Approver audit attribution without a shared-head confirmation;
66. finishes with only the original `main` freeze active; no active `release` freeze; Schedule A completed, Schedule B cancelled, and Schedule C cancelled; the primary and secondary `main` PRs open at their distinct expected SHAs; the release PR still merged; repository enforcement healthy; prior schedule, thaw, webhook, decision, publication, and activity evidence retained; and every role session still isolated and valid;
67. runs a final read-only observability phase over the real persisted activity feed, requires the complete feed to fit below its 100-event bound, and proves representative user creation, repository grants, repository setup, credential, readiness, status verification, enforcement, recovery, synchronization, freeze/lift/cancel, schedule, planned-unfreeze, and single/shared-thaw rows retain curated action, target, outcome, and detail fields; exact actor evidence remains visible for **E2E Admin**, **E2E Admin Only**, **E2E Freezer**, **E2E Thaw Approver**, **Scheduler**, and the truthful **Unknown system actor**, with newest role-boundary evidence preceding early setup history;
68. correlates 20 decision results, five current desired-status intents, 20 append-only publication attempts, and Forgejo required-context histories: the token-loss head retains its sanitized failed attempt and later recovery/current-policy attempts, the release head retains its eligible/frozen/eligible progression without a duplicate intent, and the role-boundary head retains frozen then Eligible decisions with failure then success publication evidence at the same repository, PR, branch, full SHA, context, mode, state, and descriptions;
69. exercises the real repository/event webhook controls and proves eight accumulated deliveries divide into seven processed and one retryable failure; processed and retryable filters retain truthful selected controls and summaries, received-time ascending/descending sorts reverse the fixed duplicate and terminal closed rows, opened/synchronized/closed evidence remains visible, the fixed duplicate remains one persisted row, and the invalid-signature delivery remains absent;
70. reconstructs the sanitized duplicate payload and HMAC only in memory without sending them again, then proves activity, decision, publication, and webhook pages exclude the complete payload, signature, signature-header names, invalid-signature secret, payload-only markers, generated credentials, and internal audit JSON; exact before/after user/session, repository lifecycle, active-freeze, schedule, diagnostic-page, counter, Forgejo status-history, and final PR snapshots prove every terminal read and filter query is side-effect free;
71. checks all three Forgejo token values, both generated passwords, the webhook secret, and the installation key against rendered surfaces for every role session, relevant HTTP responses and redirects, Forgejo status API responses, captured Go test output, and both container logs without printing unsafe content; and
72. removes both containers and both named volumes on success or failure.

The initial pull request and both later feature-branch advance deliveries are Forgejo-emitted. The status drift is a deliberate cooperative-enforcement fixture posted with the disposable fictional control token while Thawguard is stopped; the test does not attempt a merge while that success is newest. The rejection and duplicate probes are clearly identified synthetic E2E fixtures; they run only after credential recovery, reuse the fictional repository, and never store or print their payloads, signatures, or in-memory secret. Separate status tokens keep fixture control independent from the credential under failure, but all three tokens belong only to the disposable fictional owner.

The second lifecycle cancels an already-active freeze. Active **Cancel** records the distinct **Cancelled** outcome and republishes current policy; **Lift** records **Lifted**, while scheduled cancellation applies only to a future window that has not activated. The test does not merge after the passing status because the updated required context is sufficient proof that Thawguard removed its cooperative merge block.

The third lifecycle approves an immediate thaw for one uniquely headed PR while its branch freeze remains active. The submitted form identifies the repository, PR, target branch, and reason but does not submit a head SHA; Thawguard fetches the current head from Forgejo, records the exact-head exception, and publishes the passing status.

The synchronized-head lifecycle then advances that real PR to different code. The old exact-head approval no longer applies to the changed head, so the still-active branch freeze produces the normal failing status again. The old exception row is retained as active for its old SHA rather than expired, revoked, or permanently invalidated; returning the PR to that exact old SHA could make the approval applicable again. No invalidation audit event is invented. The retained new blocked head and unchanged active freeze prepare the same disposable fixture for shared-head confirmation coverage without implying hard enforcement against forge writers who can post statuses.

The shared-head lifecycle creates a second real open PR at that retained blocked SHA. The first ordinary thaw request returns a truthful `409 Conflict` after an audited refresh reports two open PRs, but it records no approval and publishes no status. The follow-up form carries the full server-observed SHA and an opaque affected-set fingerprint used only by the server's staleness recheck; it does not submit an affected-PR list or mutable metadata for those PRs. This smoke round-trips the untouched server-rendered values, while lower-level tests cover reconfirmation after a changed head or affected set. Explicit confirmation refreshes the forge state again, atomically approves both currently frozen PRs, records one shared audit event, and publishes one SHA-scoped success. Both PRs remain open and the branch freeze remains active, so this remains cooperative workflow evidence rather than a claim of hard enforcement against forge writers.

The scheduled lifecycle uses an independent `release` PR so it cannot alter the two-PR shared-`main` status history. It uses two schedule records because **Start Now** consumes Schedule A's pending state, while Schedule B must remain pending long enough to prove scheduled cancellation truthfully. Cancelling Schedule B is a future-window operation through `/scheduled-freezes/cancel`; it is distinct from the earlier active-freeze **Cancel**, does not republish policy, and records **Freeze schedule / Cancelled** rather than **Branch freeze / Cancelled**. Schedule A's edit submits second-precision RFC3339 UTC values to avoid browser-minute boundary races, then **Start Now** reuses the release PR's existing desired-status intent and converges its required status to failure. The active Schedule A, blocked release PR, edited planned-unfreeze instant, cancelled Schedule B history, and unchanged main fixture are intentionally retained for the following planned-unfreeze/restart row.

The planned-unfreeze restart phase stops Thawguard before Schedule A is due while leaving Forgejo and persisted volumes untouched, observes the due time pass during downtime, and relies on the immediate startup lifecycle pass rather than an HTTP action to execute the overdue row. It proves persisted schedule durability, one exact success republication through the existing desired-status intent, truthful scheduler and Unknown-system-actor activity, and a quiet subsequent lifecycle interval with no duplicate work. The terminal release merge is deliberately separate: the unique-head closed event updates webhook/cache evidence only and does not recompute or republish status. The still-open shared-head `main` PRs remain frozen-policy fixtures; none is merged.

The authorization phase uses a global Admin and three independently scoped access profiles rather than treating roles as installation-wide. A second ungranted repository proves list, dashboard, activity, and diagnostic reads stay inside each session's repository scope, while Admin retains installation-wide visibility without receiving Freeze or Thaw actions. Valid-CSRF probes and exact before/after evidence prove denied requests are side-effect free. The allowed sequence keeps all Schedule C actions with Freezer and the unique-head approval with Thaw approver. Advancing one formerly shared PR also exercises the existing previous-head recomputation invariant: the other open PR stays on the old SHA with every prior status retained, followed by one expected refreshed success for its still-applicable thaw.

The terminal observability phase performs no mutation. It reads the bounded activity, decision, status-publication, and webhook diagnostic surfaces; correlates current desired state with append-only decisions, attempts, and Forgejo status histories; exercises real webhook filters and received-time ascending/descending sorting; and verifies processed deliveries remain separate from the retained retryable token-loss failure. In-memory reconstruction proves the synthetic payload and signature never become operator-visible, while complete before/after snapshots prove diagnostic reads do not rewrite workflow evidence or final repository state.

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

The disposable smoke covers freeze/lift, active cancellation, immediate and role-attributed unique-head thaws, synchronized stale-head reevaluation, shared-head confirmation, scheduled lifecycle and restart behavior, global-Admin and repository-scoped permission boundaries, setup readiness, webhook handling, token failure, and terminal audit/diagnostic evidence. All currently listed expansion rows are covered below:

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
| P2 (covered) | Scheduled create/edit/Start Now/cancel | Two exact one-time schedules prove pending cancellation separately from Start Now, which uses the normal convergence path and reuses the desired-status intent. |
| P2 (covered) | Planned unfreeze | A persisted due unfreeze survives Thawguard-only downtime, executes once in the startup lifecycle pass, republishes success through the existing intent, stays quiet on the next pass, and leaves a terminal unique-head close free of status side effects. |
| P2 (covered) | Repository-scoped Viewer/Freezer/Thaw-approver and global Admin permissions | A second ungranted repository proves scoped visibility; zero-access creation and forced password replacement are exercised; Admin-only `/users`, setup, and manual recovery-issuance controls remain global without action-role inheritance; valid-Origin and valid-CSRF 403 probes are side-effect free; and Freezer/Thaw-approver actions retain exact attribution. |
| P3 (covered) | Audit and activity evidence | Representative persisted workflow families retain curated details and actor attribution; decisions, intents, attempts, Forgejo statuses, and filtered webhook diagnostics correlate without exposing credentials, raw payloads, signatures, or internal audit JSON, and the terminal read-only invariant remains exact. |

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
