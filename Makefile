-include .env

export THAWGUARD_SECRET_KEY
export THAWGUARD_PUBLIC_URL
export THAWGUARD_STATUS_PUBLISHER
export THAWGUARD_LIVE_STATUS_POSTING
export THAWGUARD_LIVE_STATUS_REPOSITORIES

.PHONY: fmt test build e2e-up e2e-down e2e-reset e2e-logs

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/thawguard ./cmd/thawguard

e2e-up:
	@test -n "$$THAWGUARD_SECRET_KEY" || { echo "set THAWGUARD_SECRET_KEY first; see docs/local-alpha.md"; exit 1; }
	docker compose up --build -d

e2e-down:
	docker compose down

e2e-reset:
	@test -n "$$THAWGUARD_SECRET_KEY" || { echo "set THAWGUARD_SECRET_KEY first; see docs/local-alpha.md"; exit 1; }
	docker compose down -v
	docker compose up --build -d

e2e-logs:
	docker compose logs -f thawguard
