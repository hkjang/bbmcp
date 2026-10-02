# syntax=docker/dockerfile:1

# bbmcp ships as a single self-contained image: the React console is embedded
# into the Go binary, so an air-gapped install needs only this image and a
# PostgreSQL database.

# ---- Stage 1: build the web console -------------------------------------
FROM node:22-alpine AS web

WORKDIR /src/web
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    npm_config_fund=false \
    npm_config_audit=false

COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
RUN npm run build

# ---- Stage 2: build the server ------------------------------------------
FROM golang:1.24-alpine AS server

RUN apk add --no-cache ca-certificates tzdata git

WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The console built in stage 1 replaces the placeholder before embedding.
COPY --from=web /src/internal/webui/dist ./internal/webui/dist

ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN go build -trimpath \
      -ldflags "-s -w \
        -X github.com/hkjang/bbmcp/internal/version.Version=${VERSION} \
        -X github.com/hkjang/bbmcp/internal/version.Commit=${COMMIT} \
        -X github.com/hkjang/bbmcp/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/bbmcp ./cmd/server

# ---- Stage 3: runtime ----------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl && \
    addgroup -g 10001 -S bbmcp && \
    adduser -u 10001 -S -G bbmcp -h /home/bbmcp bbmcp

ENV TZ=Asia/Seoul \
    BBMCP_ADDR=:8080

COPY --from=server /out/bbmcp /usr/local/bin/bbmcp

USER bbmcp
WORKDIR /home/bbmcp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/bbmcp"]

LABEL org.opencontainers.image.title="bbmcp" \
      org.opencontainers.image.description="Keycloak SSO 와 Bitbucket 권한 검증을 결합한 Bitbucket MCP 게이트웨이" \
      org.opencontainers.image.source="https://github.com/hkjang/bbmcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="hkjang"
