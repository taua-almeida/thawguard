# Contributing to Thawguard

Thank you for helping improve Thawguard. The project is currently a pre-alpha developer preview, so small, reviewable changes are easier to evaluate and maintain than broad rewrites.

## Before starting

1. Search the [canonical GitHub issue tracker](https://github.com/taua-almeida/thawguard/issues) for existing work.
2. Open or comment on an issue before undertaking a large feature, schema redesign, new dependency, forge integration, authentication change, or build-system change.
3. Keep the cooperative-enforcement boundary in mind: Thawguard prevents accidental merges for trusted teams; it is not an unbypassable security boundary against forge writers with sufficient status permissions.

The [Codeberg repository](https://codeberg.org/taua-almeida/thawguard) is a source mirror. GitHub remains the canonical location for roadmap and issue discussion so work does not split across trackers.

## Local development

Thawguard uses Go, SQLite, server-rendered templates, and minimal JavaScript.

```sh
go test ./...
go run ./cmd/thawguard
```

The service listens on `127.0.0.1:8080` by default. See [Testing](docs/testing.md) for fast checks and the opt-in disposable Forgejo E2E suite.

## Change guidelines

- Keep changes focused and explain the user-visible reason for them.
- Prefer standard-library and existing-project solutions. Discuss new dependencies before adding them.
- Preserve explicit authorization, CSRF, session, webhook-signature, and secret-handling boundaries.
- Use parameterized SQL and include migration tests for schema changes.
- Keep UI states truthful for empty, error, disabled, setup-incomplete, unhealthy, and read-only conditions.
- Add tests at the narrowest useful level, then run the broader suite.
- Use fictional, sanitized fixtures only. Never commit real tokens, secrets, webhook payloads, repository data, local database files, or machine-specific paths.
- Do not weaken or overwrite unrelated forge branch-protection settings.

## Verification

For most changes:

```sh
gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./...
git diff --check
```

Run `make e2e` only for changes that affect the real Forgejo integration, enforcement lifecycle, authentication boundaries, scheduling lifecycle, webhook processing, or status publication. Ordinary unit tests must not start Docker.

## Pull requests

Include:

- the problem and intended outcome;
- the issue being addressed;
- important scope exclusions or trade-offs;
- tests and manual checks performed;
- screenshots for meaningful UI changes, using fictional data only;
- migration and rollback considerations when persistence changes.

Keep commits concise and avoid mixing unrelated cleanup with behavior changes.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md) and use GitHub's private security-advisory flow.
