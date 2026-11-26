#!/bin/bash
set -euo pipefail
umask 077
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
image=ismanager-ad-fixture:test
tmp=$(mktemp -d)
name=ismanager-ad-test-$(openssl rand -hex 6)
network=$name
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
docker build -t "$image" "$here"
docker network create --internal "$network" >/dev/null
SERVICE_PASS="$(openssl rand -hex 20)Qb!"
USER_PASS="$(openssl rand -hex 20)Rw!"
export SERVICE_PASS USER_PASS
docker run -d --name "$name" --hostname dc --network "$network" -e SERVICE_PASS -e USER_PASS "$image" >/dev/null
TEST_DC=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
export TEST_DC
ready() { docker exec "$name" bash -ec 'exec 4<>/dev/tcp/127.0.0.1/636' >/dev/null 2>&1; }
for _ in $(seq 1 90); do
  ready && break
  [[ $(docker inspect --format '{{.State.Running}}' "$name") == true ]] || break
  sleep 1
done
ready || { docker logs "$name" 2>&1 | tail -30; exit 1; }
docker cp "$name:/var/lib/samba/private/tls/ca.pem" "$tmp/ca.pem" >/dev/null
export TEST_CA="$tmp/ca.pem"
cd "$repo"
PYTHONPATH="$repo/tests:$repo" "${PYTHON:-$repo/.venv/bin/python}" -m pytest -q "$here/live.py" "$@"
