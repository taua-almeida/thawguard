# Thawguard Roadmap

Thawguard is a pre-alpha self-hosted branch-freeze controller for trusted teams. This roadmap communicates direction, not release dates or guarantees. Scope may change as workflows are tested with maintainers.

GitHub is the [canonical issue tracker](https://github.com/taua-almeida/thawguard/issues), with a [pinned roadmap discussion](https://github.com/taua-almeida/thawguard/issues/7). The [Codeberg repository](https://codeberg.org/taua-almeida/thawguard) mirrors the source and this versioned roadmap without maintaining a duplicate issue backlog.

## Now: Scheduled Freezes v2

- Add [named recurring weekly freeze windows](https://github.com/taua-almeida/thawguard/issues/2).
- Store and display an explicit timezone for every recurring schedule.
- Define daylight-saving behavior for skipped and repeated local times.
- [Make freeze reasons optional and improve status descriptions](https://github.com/taua-almeida/thawguard/issues/4).
- Include truthful schedule, reason, and actor context in forge-facing status descriptions within provider limits.
- Add holiday-date handling after the weekly recurrence contract is stable.

## Next: Organization readiness

- [Design organization identity and onboarding](https://github.com/taua-almeida/thawguard/issues/5), including configurable company SSO with a safe local recovery path.
- Define repository-scoped Viewer access for verified repository members who do not yet have a Thawguard account.
- Add secure email invitations and password recovery using expiring, single-use links.
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
