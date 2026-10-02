#!/usr/bin/env bash
# 개발용 기동 스크립트: PostgreSQL 컨테이너 + 모의 Bitbucket + bbmcp 서버.
#
#   scripts/dev.sh up     # 전부 기동하고 샘플 데이터를 넣습니다
#   scripts/dev.sh down   # 정리합니다
set -euo pipefail

cd "$(dirname "$0")/.."

PG_CONTAINER=bbmcp-dev-pg
PG_PORT=${PG_PORT:-15457}
BBMCP_PORT=${BBMCP_PORT:-18411}
MOCK_PORT=${MOCK_PORT:-19200}

case "${1:-up}" in
  up)
    if ! docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
      docker run -d --rm --name "${PG_CONTAINER}" \
        -e POSTGRES_USER=bbmcp -e POSTGRES_PASSWORD=bbmcp -e POSTGRES_DB=bbmcp \
        -p "${PG_PORT}:5432" postgres:16-alpine
      sleep 5
    fi

    go build -o /tmp/bbmcp-mockbitbucket hack/mockbitbucket/main.go
    /tmp/bbmcp-mockbitbucket --addr ":${MOCK_PORT}" &
    echo $! > /tmp/bbmcp-mock.pid

    (cd web && npm run build)
    go build -o bin/bbmcp ./cmd/server

    DATABASE_URL="postgres://bbmcp:bbmcp@127.0.0.1:${PG_PORT}/bbmcp?sslmode=disable" \
    BOOTSTRAP_ADMIN=admin \
    BOOTSTRAP_ADMIN_PASSWORD='bbmcpAdmin!2026' \
    ENCRYPTION_KEY="$(openssl rand -base64 32)" \
    BBMCP_ADDR=":${BBMCP_PORT}" \
      bin/bbmcp &
    echo $! > /tmp/bbmcp-dev.pid

    sleep 4
    BBMCP_URL="http://localhost:${BBMCP_PORT}" \
    MOCK_BITBUCKET="http://127.0.0.1:${MOCK_PORT}" \
      hack/seed.sh
    echo "콘솔: http://localhost:${BBMCP_PORT}  (admin / bbmcpAdmin!2026)"
    ;;
  down)
    [ -f /tmp/bbmcp-dev.pid ] && kill "$(cat /tmp/bbmcp-dev.pid)" 2>/dev/null || true
    [ -f /tmp/bbmcp-mock.pid ] && kill "$(cat /tmp/bbmcp-mock.pid)" 2>/dev/null || true
    docker rm -f "${PG_CONTAINER}" >/dev/null 2>&1 || true
    rm -f /tmp/bbmcp-dev.pid /tmp/bbmcp-mock.pid
    echo "정리했습니다."
    ;;
  *)
    echo "사용법: scripts/dev.sh [up|down]" >&2
    exit 2
    ;;
esac
