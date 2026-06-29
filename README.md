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

The service listens on `:8080` by default. Override with `THAWGUARD_HTTP_ADDR`.

The service creates `thawguard.db` by default. Override with `THAWGUARD_DB_PATH`.

Current local pages:

- `/` dashboard
- `/repositories` repository setup form and manual setup checklist

## License

Thawguard is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
