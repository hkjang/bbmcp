#!/usr/bin/env bash
# bbmcp 업그레이드: 이미지 적재 → deploy/.env 의 BBMCP_VERSION 갱신 → 재기동 →
# 실제로 새 버전이 떠 있는지 확인.
#
#   bash deploy/upgrade.sh /path/to/bbmcp-v0.2.10.tar.gz
#
# 이미지만 적재하고 docker compose up 을 하면, deploy/.env 에 남아 있는 예전
# BBMCP_VERSION 때문에 예전 이미지가 계속 돕니다. 이 스크립트는 그 값을 바꾸고,
# compose 가 새 이미지를 고르는지와 컨테이너가 새 버전으로 시작했는지 확인한 뒤에만
# 성공으로 끝납니다. deploy/.env 의 다른 값(비밀번호, 암호화 키)은 읽거나 출력하지
# 않고, 파일의 소유자와 권한을 유지합니다.
set -euo pipefail

die() { echo "업그레이드 실패: $*" >&2; exit 1; }

TARBALL="${1:-}"
[ -n "$TARBALL" ] && [ -f "$TARBALL" ] || die "이미지 파일을 지정하십시오: bash deploy/upgrade.sh bbmcp-v<버전>.tar.gz"
TARBALL="$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")"
VERSION="$(basename "$TARBALL" | sed -n 's/^bbmcp-v\(.*\)\.tar\.gz$/\1/p')"
[ -n "$VERSION" ] || die "파일 이름이 bbmcp-v<버전>.tar.gz 형식이 아닙니다: $(basename "$TARBALL")"
IMAGE="bbmcp:v${VERSION}"

cd "$(dirname "$0")"
[ -f docker-compose.yml ] || die "deploy/docker-compose.yml 이 없습니다"
[ -f .env ] || die "deploy/.env 가 없습니다. 처음 설치라면 .env.example 을 복사해 값을 채우십시오"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "docker compose 를 찾을 수 없습니다"
fi

# 셸에 내보낸 BBMCP_VERSION 은 .env 보다 우선하므로, 남아 있으면 예전 이미지가 뜹니다.
if [ -n "${BBMCP_VERSION:-}" ]; then
  echo "주의: 셸 환경의 BBMCP_VERSION=${BBMCP_VERSION} 을 이번 실행에서 무시합니다. systemd·cron 등에 설정되어 있다면 지우십시오."
  unset BBMCP_VERSION
fi

if [ -f "${TARBALL}.sha256" ]; then
  echo "== 무결성 확인 (sha256)"
  (cd "$(dirname "$TARBALL")" && sha256sum -c "$(basename "$TARBALL").sha256") || die "sha256 이 맞지 않습니다"
fi

echo "== 이미지 적재: ${IMAGE}"
docker load -i "$TARBALL" >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "적재한 파일에 ${IMAGE} 가 없습니다"

echo "== deploy/.env 의 BBMCP_VERSION 을 ${VERSION} 로 변경"
tmp="$(mktemp ./.env.upgrade.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
chmod --reference=.env "$tmp" 2>/dev/null || chmod 600 "$tmp"
chown --reference=.env "$tmp" 2>/dev/null || true
# CRLF 로 저장된 .env 도 같은 줄로 알아봅니다. 주석 처리된 줄은 건드리지 않습니다.
awk -v v="$VERSION" '
  { sub(/\r$/, "") }
  /^[[:space:]]*BBMCP_VERSION[[:space:]]*=/ { print "BBMCP_VERSION=" v; done = 1; next }
  { print }
  END { if (!done) print "BBMCP_VERSION=" v }
' .env > "$tmp"

# 바꾼 값으로 compose 가 새 이미지를 고르는지, 기존 .env 를 바꾸기 전에 확인합니다.
if ! config_out="$("${COMPOSE[@]}" -f docker-compose.yml --env-file "$tmp" config 2>&1)"; then
  die "compose 설정을 읽지 못했습니다 (deploy/.env 는 그대로입니다):
${config_out}"
fi
resolved="$(printf '%s\n' "$config_out" | awk '/image: *bbmcp:/ {print $2; exit}')"
[ "$resolved" = "$IMAGE" ] || die "compose 가 ${IMAGE} 가 아니라 '${resolved}' 를 고릅니다. deploy/docker-compose.yml 의 image 줄을 확인하십시오 (deploy/.env 는 그대로입니다)"
mv "$tmp" .env
trap - EXIT

echo "== 재기동"
"${COMPOSE[@]}" -f docker-compose.yml --env-file .env up -d

container="$("${COMPOSE[@]}" -f docker-compose.yml --env-file .env ps -q bbmcp)"
[ -n "$container" ] || die "bbmcp 컨테이너를 찾을 수 없습니다"
running="$(docker inspect "$container" --format '{{.Config.Image}}')"
[ "$running" = "$IMAGE" ] || die "실행 중인 컨테이너의 이미지가 ${running} 입니다"

echo "== 시작 확인"
for _ in $(seq 1 60); do
  if docker logs "$container" 2>&1 | grep -q "\"msg\":\"bbmcp 시작\".*\"version\":\"${VERSION}\""; then
    if docker logs "$container" 2>&1 | grep -q '"msg":"HTTP 수신 대기"'; then
      echo "업그레이드 완료: bbmcp v${VERSION}"
      echo "에이전트 PC 에서 확인: 응답 헤더 X-Bbmcp-Version 이 ${VERSION} 인지 보십시오"
      echo "  curl -sD - https://<bbmcp 주소>/.well-known/oauth-protected-resource/mcp -o /dev/null | grep -i x-bbmcp-version"
      exit 0
    fi
  fi
  sleep 2
done
docker logs --tail 20 "$container" >&2 || true
die "v${VERSION} 이 2분 안에 시작되지 않았습니다"
