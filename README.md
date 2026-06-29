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

Current local pages:

- `/` dashboard
- `/repositories` repository setup form and manual setup checklist
- `/freezes` local active branch-freeze form and list
- `/decisions` local PR status decision preview; records results locally and does not post to Forgejo/Codeberg

Current bootstrap sessions are for local development only. Do not expose the server on a network until real local auth is configured.

## License

Thawguard is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
