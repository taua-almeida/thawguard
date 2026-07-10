# Thawguard

Freeze branches. Thaw exceptions. Keep release flow auditable.

Thawguard is a self-hosted branch-freeze controller for Forgejo/Codeberg-first teams. It helps trusted maintainers pause merges into selected branches during QA, releases, deployments, or incidents, while allowing explicit audited per-PR exceptions when a fix must land.

## Status

Early Milestone 1 foundation. Not ready for production use.

## Important boundary

Thawguard is cooperative enforcement for trusted teams. It is intended to prevent accidental merges and automate auditable freeze workflows. It is not a hard security boundary against repository writers who can post forge commit statuses with sufficient token permissions.

## Local development

```sh
go test ./...
go run ./cmd/thawguard
```

The service listens on `127.0.0.1:8080` by default. Override with `THAWGUARD_HTTP_ADDR`. Until the first local admin user exists, Thawguard refuses non-loopback bind addresses for first-admin setup.

The service creates `thawguard.db` by default. Override with `THAWGUARD_DB_PATH`.

Runtime configuration is environment-variable based. The binary does not currently parse CLI flags such as `--db` or `--addr`; use `THAWGUARD_DB_PATH` and `THAWGUARD_HTTP_ADDR` instead.

For a Docker-based shadow-mode alpha with mock Codeberg repositories, see [`docs/local-alpha.md`](docs/local-alpha.md).

Repository webhook secrets and status-posting tokens are encrypted before they are stored. To enable secret/token setup in local development, set `THAWGUARD_SECRET_KEY` to a stable, high-entropy, base64-encoded 32-byte installation key. Without this key, the rest of the local UI remains usable, but webhook secret and status token setup are disabled. Losing or changing this key makes stored secrets and tokens undecryptable.

The local signed webhook receiver is `POST /webhooks/forgejo`. It verifies configured repository webhook secrets, records sanitized delivery results, updates the local PR cache, and recomputes local status/publication-intent records plus dry-run publication attempts. `THAWGUARD_STATUS_PUBLISHER` defaults to `dry_run`.

Live Forgejo/Codeberg commit-status posting is a guarded pilot mode, not the default. To start in live mode, `THAWGUARD_STATUS_PUBLISHER=forgejo_status` must be paired with `THAWGUARD_LIVE_STATUS_POSTING=enabled`, `THAWGUARD_LIVE_STATUS_REPOSITORIES=owner/name` for the specific repositories allowed to post, a valid `THAWGUARD_SECRET_KEY`, and a configured encrypted status token on each allowed repository. Repositories not on the allowlist and repositories missing tokens are recorded as failed publication attempts rather than falling back silently. Keep this mode limited to throwaway or explicitly approved repositories until the rest of the live-pilot process is reviewed.

Freeze, lift, and cancel actions recompute statuses for open PRs on the affected repository and branch. In guarded `forgejo_status` live mode, each freeze change first syncs current open PRs for the target branch from the forge using the repository's encrypted status token, then publishes only the `thawguard/freeze` status context.

Current local pages:

- `/` dashboard
- `/setup` first local admin setup when no users exist; the first account starts with all MVP roles for local bootstrap
- `/login` and `/logout` local user session flow
- `/repositories` repository setup form and manual setup checklist
- `/freezes` local active branch-freeze form and list
- `/scheduled-freezes` one-time scheduled freeze windows with optional planned unfreeze
- `/decisions` immediate thaw approval; fetches the current PR head from the forge in live mode and scopes the thaw to that PR/head SHA
- `/publications` latest idempotent local status publication intents and dry-run publication attempts; shows what would be posted later and does not post to Forgejo/Codeberg
- `/webhooks` system activity, status publication attempts, and recent signed webhook delivery metadata; shows sanitized local processing history and does not store raw payloads, signatures, or secrets
- `/users` admin-only local user and multi-role management

Local users can hold one or more explicit role flags. Admin configures repositories/users/secrets, freezer performs freeze actions, thaw approver approves PR exceptions, and viewer is read-only. If you bind beyond loopback after first-admin setup, keep Thawguard behind the network controls appropriate for your trusted team.

## License

Thawguard is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
