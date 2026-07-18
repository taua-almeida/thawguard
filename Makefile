-include .env

export THAWGUARD_SECRET_KEY
export THAWGUARD_PUBLIC_URL

LOCAL_COMPOSE = docker compose --project-name thawguard-local --file compose.yaml --file compose.local.yaml

# Frontend tooling (dev-only): the Tailwind standalone CLI lives at bin/tailwindcss
# (gitignored, never committed). Fetch and verify it with:
#   curl -fsSLo bin/tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-x64
#   echo "dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a  bin/tailwindcss" | sha256sum -c
#   chmod +x bin/tailwindcss
# The compiled web/static/app.css is committed, so build/test stay Go-only.
TAILWIND = bin/tailwindcss

.PHONY: fmt test build css css-watch dev local-up local-down local-reset local-logs e2e e2e-keep

css:
	@test -x $(TAILWIND) || { echo "$(TAILWIND) missing; see the comment above the css target in Makefile"; exit 1; }
	$(TAILWIND) --input web/styles/app.css --output web/static/app.css --minify

css-watch:
	@test -x $(TAILWIND) || { echo "$(TAILWIND) missing; see the comment above the css target in Makefile"; exit 1; }
	$(TAILWIND) --input web/styles/app.css --output web/static/app.css --watch

dev: css
	THAWGUARD_DEV=1 go run ./cmd/thawguard

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
