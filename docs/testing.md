# Testing

## Fast local checks

Run the normal test suite without containers or live forge credentials:

```sh
go test ./...
go vet ./...
go build ./...
```

Package and handler tests use temporary databases, sanitized fixtures, and local HTTP test servers. Ordinary `go test ./...` must remain Docker-free.

## Disposable Forgejo E2E

The opt-in end-to-end suite provisions a fresh local Forgejo and Thawguard stack, creates fictional users and repositories, exercises signed webhooks and real status posting, and removes its containers and volumes when the run finishes:

```sh
make e2e
```

Requirements:

- Docker with Docker Compose
- Go
- OpenSSL
- ports `127.0.0.1:3000` and `127.0.0.1:8080` available

The E2E suite is build-tagged and environment-gated. It generates disposable credentials in memory and must never use real GitHub, Codeberg, Forgejo, or Gitea credentials. See [Local Forgejo integration and E2E](local-alpha.md) for the behavior matrix, cleanup guarantees, and failure-trap command.

## Persistent manual stack

For interactive local testing with retained Docker volumes:

```sh
make local-up
make local-logs
make local-down
```

Use `make local-reset` only when the fictional local Forgejo and Thawguard data can be discarded. Never commit `.env`, local database files, tokens, webhook secrets, generated passwords, or real webhook payloads.
