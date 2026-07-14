-include .env

export THAWGUARD_SECRET_KEY
export THAWGUARD_PUBLIC_URL

LOCAL_COMPOSE = docker compose --project-name thawguard-local --file compose.yaml --file compose.local.yaml

.PHONY: fmt test build local-up local-down local-reset local-logs e2e e2e-keep

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/thawguard ./cmd/thawguard

local-up:
	@test -n "$$THAWGUARD_SECRET_KEY" || { echo "set THAWGUARD_SECRET_KEY first; see docs/local-alpha.md"; exit 1; }
	$(LOCAL_COMPOSE) up --build --detach --wait --wait-timeout 180

local-down:
	@THAWGUARD_SECRET_KEY="$${THAWGUARD_SECRET_KEY:-unused-for-compose-down}" $(LOCAL_COMPOSE) down --remove-orphans

local-reset:
	@test -n "$$THAWGUARD_SECRET_KEY" || { echo "set THAWGUARD_SECRET_KEY first; see docs/local-alpha.md"; exit 1; }
	$(LOCAL_COMPOSE) down --volumes --remove-orphans
	$(LOCAL_COMPOSE) up --build --detach --wait --wait-timeout 180

local-logs:
	@THAWGUARD_SECRET_KEY="$${THAWGUARD_SECRET_KEY:-unused-for-compose-logs}" $(LOCAL_COMPOSE) logs --follow thawguard forgejo

e2e:
	bash scripts/e2e.sh

e2e-keep:
	E2E_KEEP_ON_FAILURE=1 bash scripts/e2e.sh
