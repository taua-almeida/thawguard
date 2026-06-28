# Thawguard

Freeze branches. Thaw exceptions. Keep release flow auditable.

Thawguard is a self-hosted branch-freeze controller for Forgejo/Codeberg-first teams. It helps trusted maintainers pause merges into selected branches during QA, releases, deployments, or incidents, while allowing explicit audited per-PR exceptions when a fix must land.

## Status

Early local scaffold. Not ready for production use.

## Important boundary

Thawguard is cooperative enforcement for trusted teams. It is intended to prevent accidental merges and automate auditable freeze workflows. It is not a hard security boundary against repository writers who can post forge commit statuses with sufficient token permissions.

## Local development

```sh
go test ./...
go run ./cmd/thawguard
```

The service listens on `:8080` by default. Override with `THAWGUARD_HTTP_ADDR`.

## License

License is not chosen yet. Choose a license before publishing this repository as open source.
