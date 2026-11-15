#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp_base="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
lab_dir="$(mktemp -d "$tmp_base/opsark-docker-bootstrap.XXXXXXXX")"

cleanup() {
    case "$lab_dir" in
        "$tmp_base"/opsark-docker-bootstrap.*) rm -rf -- "$lab_dir" ;;
        *) printf '%s\n' 'Refusing to remove an unexpected bootstrap directory.' >&2 ;;
    esac
}
trap cleanup EXIT

if [[ "${OPSARK_DISPOSABLE_DOCKER_LAB:-}" != 1 ]]; then
    printf '%s\n' 'Set OPSARK_DISPOSABLE_DOCKER_LAB=1 only on a disposable, authorized runner.' >&2
    exit 1
fi

env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host unix:///var/run/docker.sock pull python:3.13-slim

cd -- "$repo_root"
export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"
export OPSARK_DATA_DIR="$lab_dir/data"
unset OPSARK_TOKEN OPSARK_INVENTORY OPSARK_AI_BASE_URL OPSARK_AI_KEY OPSARK_AI_MODEL
unset OPSARK_OBSERVE_ENABLED OPSARK_OBSERVE_HOSTS OPSARK_OBSERVE_INTERVAL
unset OPSARK_WEB_OBSERVE_ENABLED
uv run python tests/docker_lab_smoke.py
uv run python tests/docker_config_lab.py
