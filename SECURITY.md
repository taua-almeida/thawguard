# Security Policy

## Project status

Thawguard is a pre-alpha developer preview and has no production-supported release line yet. Security reports against the current `main` branch are still welcome.

## Reporting a vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use the repository's [private security-advisory form](https://github.com/taua-almeida/thawguard/security/advisories/new). Include enough detail to reproduce and assess the issue, but do not include real production secrets, tokens, webhook payloads, repository data, or personal information.

Useful reports may cover:

- authentication, authorization, sessions, CSRF, or password handling;
- webhook signature verification and replay/idempotency behavior;
- secret or status-token encryption, storage, redaction, or rotation;
- repository isolation or unintended private-data disclosure;
- status publication that escapes the configured repository/branch scope;
- unsafe setup, activation, recovery, or deactivation behavior.

Maintainers will evaluate the report privately and coordinate disclosure when a fix and affected scope are understood. Because the project is pre-alpha, no response or release-time service-level agreement is currently promised.

## Cooperative-enforcement boundary

Thawguard is designed to prevent accidental merges and automate auditable freeze workflows for trusted teams. It is not a hard security boundary against a forge collaborator who already has enough permission to post or override the required commit status, alter branch protection, or bypass repository policy.

A report that demonstrates Thawguard leaking credentials, crossing configured repository boundaries, accepting forged webhooks, escalating application roles, or publishing statuses outside its authorized scope is still a security concern. The documented forge-writer limitation does not excuse defects inside Thawguard's own trust boundary.

## Safe testing

- Use disposable local repositories and fictional identities.
- Prefer the documented local Forgejo E2E environment.
- Do not test against repositories, users, or infrastructure you do not own or have explicit permission to assess.
- Do not include exploit payloads containing real credentials or private data in public issues or pull requests.
