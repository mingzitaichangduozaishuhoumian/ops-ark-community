#!/usr/bin/env bash
set -euo pipefail

export OPSARK_LAB_BASE_IMAGE="${OPSARK_LAB_BASE_IMAGE:-ubuntu:24.04}"
case "$OPSARK_LAB_BASE_IMAGE" in
    ubuntu:24.04|debian:12|debian:13) ;;
    *) printf '%s\n' 'Unsupported lab image; choose ubuntu:24.04, debian:12 or debian:13.' >&2; exit 1 ;;
esac

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp_base="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
lab_dir="$(mktemp -d "$tmp_base/opsark-lab.XXXXXXXX")"
stack_started=0
export OPSARK_LAB_KEY_DIR="$lab_dir"
export OPSARK_LAB_SSH_PORT="${OPSARK_LAB_SSH_PORT:-22220}"

docker_local() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        docker --host unix:///var/run/docker.sock "$@"
}

compose() {
    docker_local compose -p opsark-lab -f "$repo_root/tests/lab/compose.yaml" "$@"
}

cleanup() {
    local exit_code=$?
    if [[ "$stack_started" == 1 ]]; then
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    case "$lab_dir" in
        "$tmp_base"/opsark-lab.*) rm -rf -- "$lab_dir" ;;
        *) printf '%s\n' 'Refusing to remove an unexpected lab directory.' >&2 ;;
    esac
    return "$exit_code"
}
trap cleanup EXIT

if [[ -n "$(docker_local ps -aq --filter label=com.docker.compose.project=opsark-lab)" ]]; then
    printf '%s\n' 'An opsark-lab stack already exists; refusing to reuse or remove it.' >&2
    exit 1
fi

ssh-keygen -q -t ed25519 -N '' -f "$lab_dir/client_key"
printf 'Testing isolated target image: %s\n' "$OPSARK_LAB_BASE_IMAGE"
stack_started=1
compose up --build --wait --wait-timeout 120
container_id="$(compose ps -q target)"
test -n "$container_id"
docker_local cp "$container_id:/etc/ssh/ssh_host_ed25519_key.pub" "$lab_dir/host_key.pub" >/dev/null
read -r key_type key_value _ < "$lab_dir/host_key.pub"
printf '[127.0.0.1]:%s %s %s\n' "$OPSARK_LAB_SSH_PORT" "$key_type" "$key_value" > "$lab_dir/known_hosts"
chmod 600 "$lab_dir/known_hosts"

cd -- "$repo_root"
export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"
export OPSARK_DATA_DIR="$lab_dir/bootstrap-data"
unset OPSARK_TOKEN OPSARK_INVENTORY OPSARK_AI_BASE_URL OPSARK_AI_KEY OPSARK_AI_MODEL
unset OPSARK_OBSERVE_ENABLED OPSARK_OBSERVE_HOSTS OPSARK_OBSERVE_INTERVAL
unset OPSARK_WEB_OBSERVE_ENABLED
uv run python tests/lab_smoke.py
