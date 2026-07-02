# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.3

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/thawguard ./cmd/thawguard

FROM debian:bookworm-slim
WORKDIR /app

COPY --from=build /out/thawguard /usr/local/bin/thawguard
COPY migrations ./migrations
COPY web ./web

RUN mkdir -p /data && chown -R 10001:10001 /app /data

USER 10001:10001
ENV THAWGUARD_HTTP_ADDR=127.0.0.1:8080
ENV THAWGUARD_DB_PATH=/data/thawguard.db
ENV THAWGUARD_PUBLIC_URL=http://127.0.0.1:8080
ENV THAWGUARD_STATUS_PUBLISHER=dry_run

EXPOSE 8080
ENTRYPOINT ["thawguard"]
