# Thawguard Roadmap

Thawguard is a pre-alpha self-hosted branch-freeze controller for trusted teams. This roadmap communicates direction, not release dates or guarantees. Scope may change as workflows are tested with maintainers.

GitHub is the [canonical issue tracker](https://github.com/taua-almeida/thawguard/issues), with a [pinned roadmap discussion](https://github.com/taua-almeida/thawguard/issues/7). The [Codeberg repository](https://codeberg.org/taua-almeida/thawguard) mirrors the source and this versioned roadmap without maintaining a duplicate issue backlog.

## Shipped: Scheduled Freezes v2

Documented in [docs/scheduled-freezes.md](docs/scheduled-freezes.md).

- [Named recurring weekly freeze windows](https://github.com/taua-almeida/thawguard/issues/2), with rules that may wrap across the week boundary.
- An explicit persisted IANA timezone for every recurring schedule, stored and displayed by zone name.
- Defined daylight-saving behavior: skipped local times resolve past the gap, repeated local times resolve so coverage is never shortened.
- [Optional freeze reasons and improved status descriptions](https://github.com/taua-almeida/thawguard/issues/4).
- Truthful schedule, reason, and actor context in forge-facing status descriptions within provider limits.
- Named dated freeze windows entered manually on a dated schedule; there is no bundled holiday calendar, and month/year recurrence is not implemented.

## In progress: Organization readiness

- **Shipped:** repository-scoped authorization and Users & Access management under the [organization identity and onboarding](https://github.com/taua-almeida/thawguard/issues/5) milestone.
- **Shipped:** [manual invitation and password-recovery links](https://github.com/taua-almeida/thawguard/issues/11), including atomic invitation acceptance and replay-safe replacement. [Optional email delivery and public recovery](https://github.com/taua-almeida/thawguard/issues/15) and [sole-Administrator recovery policy](https://github.com/taua-almeida/thawguard/issues/16) remain focused follow-ups.
- **Shipped:** the Administrator-only first release of [one configurable company OIDC connection](https://github.com/taua-almeida/thawguard/issues/13), including encrypted client-secret storage, discovery/JWKS health, Test sign-in, verified email/domain admission, explicit Administrator linking, operational login sessions, revocation, and local-password recovery.
- **Verified:** the supervised [real-provider and browser smoke test](https://github.com/taua-almeida/thawguard/issues/17) is complete. Next, expand to [explicit linking for existing local users](https://github.com/taua-almeida/thawguard/issues/18), followed by [zero-access account creation on first verified sign-in](https://github.com/taua-almeida/thawguard/issues/19).
- After identity and account-creation boundaries are stable, define [repository-scoped Viewer access from verified forge membership](https://github.com/taua-almeida/thawguard/issues/12).
- Preserve explicit Freezer, Thaw approver, and Administrator grants; elevated roles will not be assigned automatically.

## Next: GitHub connectivity

- [Add GitHub.com and GitHub Enterprise Server](https://github.com/taua-almeida/thawguard/issues/1) through a least-privilege GitHub App installation.
- Validate webhook, pull-request, status/check, branch-protection, and ruleset behavior before claiming support.
- Keep repository connectivity separate from login SSO and never link identities by unverified email alone.

## Later and under investigation

- [Investigate Gitea](https://github.com/taua-almeida/thawguard/issues/6) as a separately tested forge adapter rather than assuming Forgejo API parity.
- [Let repository setup optionally configure the required `thawguard/freeze` status](https://github.com/taua-almeida/thawguard/issues/3) when the provider supports safe, reversible branch-protection changes.
- Add retention, export, and deeper history controls as real installation data warrants them.

## Product boundary

Thawguard provides cooperative enforcement for trusted teams. It prevents accidental merges and automates auditable freeze workflows. It is not a hard security boundary against forge writers who can post or override commit statuses with sufficient permission.
