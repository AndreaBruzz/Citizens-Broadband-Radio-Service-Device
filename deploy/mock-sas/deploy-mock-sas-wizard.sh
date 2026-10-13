#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --help && $# == 1 ]]; then
    printf '%s\n' 'Interactive test-only deployment or offline packaging; no action before explicit confirmation.' \
        'Usage: bash deploy-mock-sas-wizard.sh [--help]' \
        'Requires Linux, Python with deploy/mock-sas/requirements.txt and OpenSSH for deployment.' \
        'Set PYTHON to an existing Python/venv executable if needed.'
    exit 0
fi
[[ $# == 0 ]] || { printf 'ERROR: Unsupported arguments; use --help.\n' >&2; exit 1; }
python=${PYTHON:-"$directory/../../.venv/bin/python"}
if [[ -z ${PYTHON:-} && ! -x $python ]]; then python=python3; fi
command -v -- "$python" >/dev/null || { printf 'ERROR: Python missing; create the documented local environment first.\n' >&2; exit 1; }
exec "$python" "$directory/deployment_wizard.py"
