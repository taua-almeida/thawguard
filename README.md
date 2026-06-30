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

The service listens on `127.0.0.1:8080` by default. Override with `THAWGUARD_HTTP_ADDR`; while bootstrap sessions are active, Thawguard refuses non-loopback bind addresses.

The service creates `thawguard.db` by default. Override with `THAWGUARD_DB_PATH`.

Repository webhook secrets are encrypted before they are stored. To enable webhook secret setup in local development, set `THAWGUARD_SECRET_KEY` to a stable, high-entropy, base64-encoded 32-byte installation key. Without this key, the rest of the local UI remains usable, but webhook secret setup is disabled. Losing or changing this key makes stored webhook secrets undecryptable.

The local signed webhook receiver is `POST /webhooks/forgejo`. It verifies configured repository webhook secrets, records sanitized delivery results, updates the local PR cache, and recomputes local status/publication-intent records. It does not post live statuses to Forgejo/Codeberg yet.

Current local pages:

- `/` dashboard
- `/repositories` repository setup form and manual setup checklist
- `/freezes` local active branch-freeze form and list
- `/decisions` local PR status decision preview; records results locally and does not post to Forgejo/Codeberg
- `/publications` latest idempotent local status publication intents; shows what would be posted later and does not post to Forgejo/Codeberg
- `/webhooks` recent signed webhook delivery metadata; shows sanitized local processing history and does not store raw payloads, signatures, or secrets

Current bootstrap sessions are for local development only. Do not expose the server on a network until real local auth is configured.

## License

Thawguard is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
