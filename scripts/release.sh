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

# 배포 파일 묶음. 이미지만 옮기면 운영 서버의 docker-compose.yml 과 .env 는
# 예전 것 그대로라, 업그레이드 스크립트와 함께 같은 릴리스에 싣습니다.
# 작업 트리(WSL 의 /mnt/c)는 모든 파일이 0777 로 보이므로, 권한과 소유자를 정해
# 둔 사본으로 묶습니다. 그대로 묶으면 root 로 풀었을 때 누구나 쓸 수 있는
# upgrade.sh 가 됩니다.
DEPLOY="bbmcp-deploy-${TAG}.tar.gz"
STAGE="$(mktemp -d)"
install -D -m 0644 deploy/docker-compose.yml "${STAGE}/deploy/docker-compose.yml"
install -D -m 0644 deploy/.env.example "${STAGE}/deploy/.env.example"
install -D -m 0755 deploy/upgrade.sh "${STAGE}/deploy/upgrade.sh"
chmod 0755 "${STAGE}/deploy"
tar -C "${STAGE}" --owner=0 --group=0 --numeric-owner -czf "${DEPLOY}" deploy
rm -rf "${STAGE}"
sha256sum "${DEPLOY}" > "${DEPLOY}.sha256"

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
  echo "## 업그레이드 (이미 운영 중)"
  echo
  echo "이미지만 적재하고 \`docker compose up -d\` 를 하면 deploy/.env 의 예전 BBMCP_VERSION 때문에 **예전 버전이 계속 돕니다**."
  echo "${DEPLOY} 의 deploy/upgrade.sh 를 쓰거나, BBMCP_VERSION=${VERSION} 로 바꾼 뒤 기동하십시오."
  echo
  echo '```bash'
  echo "bash deploy/upgrade.sh ${TARBALL}    # 적재, BBMCP_VERSION 변경, 재기동, 새 버전 기동 확인"
  echo '```'
  echo
  echo "확인 (에이전트 PC 에서): 응답 헤더 \`X-Bbmcp-Version: ${VERSION}\`"
  echo
  echo '```bash'
  echo "curl -sD - https://<bbmcp 주소>/.well-known/oauth-protected-resource/mcp -o /dev/null | grep -i x-bbmcp-version"
  echo '```'
  echo
  echo "## 새로 설치"
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
  echo "| 배포 파일 | \`${DEPLOY}\` (docker-compose.yml, .env.example, upgrade.sh) |"
  echo "| SHA-256 | \`$(cut -d' ' -f1 "${DEPLOY}.sha256")\` |"
  echo
  echo "SHA-256 은 파일이 손상되지 않았는지(무결성)를 확인할 뿐, 누가 만들었는지를 증명하지는 않습니다."
  echo
  echo "문서: https://hkjang.github.io/bbmcp/"
} > "${NOTES_FILE}"

if gh release view "${TAG}" >/dev/null 2>&1; then
  gh release upload "${TAG}" "${TARBALL}" "${TARBALL}.sha256" "${DEPLOY}" "${DEPLOY}.sha256" --clobber
else
  gh release create "${TAG}" "${TARBALL}" "${TARBALL}.sha256" "${DEPLOY}" "${DEPLOY}.sha256" \
    --title "bbmcp ${TAG}" --notes-file "${NOTES_FILE}"
fi
rm -f "${NOTES_FILE}"

echo "릴리스 완료: ${TAG}"
