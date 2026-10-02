#!/usr/bin/env bash
# bbmcp 릴리스 스크립트.
#
# 오프라인망에서 운영 가능한 서비스 도커 이미지만 tar.gz 로 묶어 GitHub 릴리스에
# 올립니다. 이미지 이름은 bbmcp:v<버전>, 산출물은 bbmcp-v<버전>.tar.gz 입니다.
#
#   scripts/release.sh            # VERSION 파일의 버전으로 릴리스
#   scripts/release.sh --dry-run  # 빌드와 패키징까지만 수행
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(cat VERSION)"
TAG="v${VERSION}"
IMAGE="bbmcp:${TAG}"
TARBALL="bbmcp-${TAG}.tar.gz"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

echo "== bbmcp ${TAG} 릴리스 =="

if [ -n "$(git status --porcelain)" ]; then
  echo "작업 트리가 깨끗하지 않습니다. 커밋 후 다시 실행하십시오." >&2
  git status --short >&2
  exit 1
fi

scripts/build.sh --save

if [ "$DRY_RUN" -eq 1 ]; then
  echo "건식 실행이므로 태그와 릴리스를 생성하지 않습니다."
  exit 0
fi

if ! git rev-parse "${TAG}" >/dev/null 2>&1; then
  git tag -a "${TAG}" -m "bbmcp ${TAG}"
fi
git push origin "${TAG}"

NOTES_FILE="$(mktemp)"
{
  echo "오프라인망에서 운영 가능한 서비스 도커 이미지입니다."
  echo
  echo '```bash'
  echo "# 1) 이미지 적재"
  echo "docker load -i ${TARBALL}"
  echo
  echo "# 2) 환경변수 준비 (네 개만 필요합니다)"
  echo "cp deploy/.env.example deploy/.env && \$EDITOR deploy/.env"
  echo
  echo "# 3) 기동"
  echo "docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d"
  echo '```'
  echo
  echo "| 항목 | 값 |"
  echo "|---|---|"
  echo "| 이미지 | \`${IMAGE}\` |"
  echo "| 파일 | \`${TARBALL}\` |"
  echo "| SHA-256 | \`$(cut -d' ' -f1 "${TARBALL}.sha256")\` |"
  echo
  echo "문서: https://hkjang.github.io/bbmcp/"
} > "${NOTES_FILE}"

if gh release view "${TAG}" >/dev/null 2>&1; then
  gh release upload "${TAG}" "${TARBALL}" "${TARBALL}.sha256" --clobber
else
  gh release create "${TAG}" "${TARBALL}" "${TARBALL}.sha256" \
    --title "bbmcp ${TAG}" --notes-file "${NOTES_FILE}"
fi
rm -f "${NOTES_FILE}"

echo "릴리스 완료: ${TAG}"
