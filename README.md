# Thawguard

Freeze branches. Thaw exceptions. Keep release flow auditable.

Thawguard is a self-hosted branch-freeze controller for Forgejo/Codeberg-first teams. It helps trusted maintainers pause merges into selected branches during QA, releases, deployments, or incidents, while allowing explicit audited per-PR exceptions when a fix must land.

## Status

Early Milestone 1 foundation. Not ready for production use.

## Important boundary

Thawguard is cooperative enforcement for trusted teams. It is intended to prevent accidental merges and automate auditable freeze workflows. It is not a hard security boundary against repository writers who can post forge commit statuses with sufficient token permissions.

## How enforcement works

Thawguard has one operational mode. Each repository carries a persisted enforcement state:

- New and existing repositories start **setup incomplete**. Setup (encrypted webhook secret, encrypted status token, signed webhook deliveries) and read-only readiness checks stay fully available, but no commit status is ever posted and freeze, scheduled-freeze, and thaw actions are rejected.
- An **enforcement-active** repository has one behavior: freeze lifecycle actions synchronize current open pull requests from the forge, evaluate each affected head SHA across the whole repository (including PRs on other target branches sharing the same commit), and post the real `thawguard/freeze` commit status. A missing token or forge failure fails closed: no stale status is posted, and failures during posting are recorded as sanitized failed attempts.

Read-only readiness checks verify pull-request access, branch protection for every exact managed branch, required status checks, the exact `thawguard/freeze` context, and recent signed `pull_request` webhook evidence. They never post a synthetic status. Status-post permission therefore remains explicitly unverified, and setup-incomplete repositories do not become ready. A later controlled status-post test will implement activation. There is no shadow or dry-run runtime mode.

## Managed branches

Each repository has an explicit list of managed branches: the exact branch names Thawguard may freeze or schedule. There are no globs, patterns, prefixes, or rules — `release/1.4` manages exactly the branch named `release/1.4`, and `release/*` would be a literal branch name, never a pattern.

- Every repository always manages at least its default branch; the default branch cannot be removed.
- Admins add or remove exact branch names on `/repositories`. Removal is rejected while the branch has an active or pending scheduled freeze; ended or cancelled history never blocks removal.
- Branch scope is locked while a repository is enforcement-active.
- Freeze and scheduled-freeze creation are rejected server-side for any branch that is not managed for the selected repository.
- Newly added branches are unverified until an administrator runs readiness checks and the forge confirms their setup.

## Local development

```sh
go test ./...
go run ./cmd/thawguard
```

The service listens on `127.0.0.1:8080` by default. Override with `THAWGUARD_HTTP_ADDR`. Until the first local admin user exists, Thawguard refuses non-loopback bind addresses for first-admin setup.

The service creates `thawguard.db` by default. Override with `THAWGUARD_DB_PATH`.

Runtime configuration is environment-variable based. The binary does not currently parse CLI flags such as `--db` or `--addr`; use `THAWGUARD_DB_PATH` and `THAWGUARD_HTTP_ADDR` instead.

For a Docker-based local alpha runbook, see [`docs/local-alpha.md`](docs/local-alpha.md).

Repository webhook secrets and status-posting tokens are encrypted before they are stored. To enable secret/token setup in local development, set `THAWGUARD_SECRET_KEY` to a stable, high-entropy, base64-encoded 32-byte installation key. Without this key, the rest of the local UI remains usable, but webhook secret and status token setup are disabled. Losing or changing this key makes stored secrets and tokens undecryptable.

The local signed webhook receiver is `POST /webhooks/forgejo`. It verifies configured repository webhook secrets and records sanitized delivery results. For a setup-incomplete repository it also refreshes the local PR cache as setup evidence; for an enforcement-active repository it additionally recomputes and posts the `thawguard/freeze` status.

Current local pages:

- `/` dashboard
- `/setup` first local admin setup when no users exist; the first account starts with all MVP roles for local bootstrap
- `/login` and `/logout` local user session flow
- `/repositories` repository setup form, enforcement state, managed branch scope, and read-only readiness evidence
- `/freezes` active branch-freeze form and list (requires an enforcement-active repository)
- `/scheduled-freezes` one-time scheduled freeze windows with optional planned unfreeze (requires an enforcement-active repository)
- `/decisions` immediate thaw approval; fetches the current PR head from the forge and scopes the thaw to that PR/head SHA (requires an enforcement-active repository)
- `/publications` latest desired statuses and live posting attempts (posted/failed)
- `/webhooks` system activity, status publication attempts, and recent signed webhook delivery metadata; shows sanitized local processing history and does not store raw payloads, signatures, or secrets
- `/users` admin-only local user and multi-role management

Local users can hold one or more explicit role flags. Admin configures repositories/users/secrets, freezer performs freeze actions, thaw approver approves PR exceptions, and viewer is read-only. If you bind beyond loopback after first-admin setup, keep Thawguard behind the network controls appropriate for your trusted team.

## License

Thawguard is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
