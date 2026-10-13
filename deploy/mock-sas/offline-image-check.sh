#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { printf 'Usage: %s existing-local-image\n' "$0" >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
command -v docker >/dev/null || { printf 'Docker unavailable; image checks not executed.\n' >&2; exit 1; }
docker image inspect "$1" >/dev/null
docker run --rm --pull never --network none --read-only --user 10001:10001 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --mount "type=bind,src=$ROOT,dst=/checks,readonly" \
    --env PYTHONDONTWRITEBYTECODE=1 --env SAS_SOURCE=/opt/mock-sas \
    "$1" python /checks/deploy/mock-sas/offline-image-check.py
