#!/bin/sh
# Run inside WSL/Linux with permission to use the local Docker daemon.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
mkdir -p .local
artifacts=$(mktemp -d "$project_root/.local/container-smoke.XXXXXX")
project="openrmm-check-$(date +%s)-$$"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
cat > "$artifacts/override.yaml" <<EOF
services:
  server:
    ports: !override
      - "127.0.0.1:$port:8443"
EOF
compose() {
    docker compose --env-file deploy/local.env -f compose.yaml -f "$artifacts/override.yaml" -p "$project" "$@"
}
cleanup() {
    # These resources belong to this unique test project. The normal development
    # project's data and certificates are never mounted or removed by this test.
    compose down --volumes >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
printf 'FROM scratch\nCOPY . /\n' > "$artifacts/context.Dockerfile"
docker build --quiet --file "$artifacts/context.Dockerfile" --output "type=local,dest=$artifacts/context" . >/dev/null
for excluded in .env .local dist .git web/node_modules internal/server/webui/dist; do
    [ ! -e "$artifacts/context/$excluded" ] || { echo 'Private or generated files entered the Docker build context.' >&2; exit 1; }
done
echo 'Build context excludes credentials, local state, binaries, and Git metadata.'
compose run --rm --no-deps certificates
compose up -d --wait --wait-timeout 60 server
container=$(compose ps -q server)
docker inspect --format '{{json .NetworkSettings.Ports}}' "$container" > "$artifacts/ports.json"
python3 - "$artifacts/ports.json" "$port" <<'PY'
import json, sys
ports = json.load(open(sys.argv[1], encoding="utf-8"))
assert ports == {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": sys.argv[2]}], "8444/tcp": None}, ports
PY
security=$(docker inspect --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}}' "$container")
[ "$security" = '10001:10001 true ["ALL"]' ] || { echo 'Container security configuration differs from expected values.' >&2; exit 1; }
compose exec -T server /openrmm-agent -server https://127.0.0.1:8443 -ca /tls/local/ca.pem -ready
docker cp "$container:/tls/local/ca.pem" "$artifacts/ca.pem"
for private_directory in data tls secrets; do
    # The scratch runtime has no stat/shell. Inspect copied directory metadata
    # locally, without printing file contents (which may include private keys).
    docker cp "$container:/$private_directory" - | python3 -c 'import sys, tarfile; archive=tarfile.open(fileobj=sys.stdin.buffer, mode="r|*"); entry=next(iter(archive)); assert entry.isdir() and entry.mode & 0o777 == 0o700, "Application volume directory must be private"; list(archive)'
done
echo 'Data, TLS, and administrator-key volume directories are private (0700).'
curl --silent --show-error --fail --noproxy '*' --max-time 5 --cacert "$artifacts/ca.pem" "https://127.0.0.1:$port/readyz"
before=$(compose exec -T server /openrmm-server -storage-info)
compose restart server
compose up -d --wait --wait-timeout 60 server
after_restart=$(compose exec -T server /openrmm-server -storage-info)
[ "$before" = "$after_restart" ] || { echo 'Database record changed after restart.' >&2; exit 1; }
compose up -d --force-recreate --wait --wait-timeout 60 server
after_recreate=$(compose exec -T server /openrmm-server -storage-info)
[ "$before" = "$after_recreate" ] || { echo 'Database record changed after container replacement.' >&2; exit 1; }
compose run --rm --no-deps certificates -out /tls/unrelated
set +e
compose exec -T server /openrmm-agent -server https://127.0.0.1:8443 -ca /tls/unrelated/ca.pem -ready
untrusted_status=$?
set -e
[ "$untrusted_status" -eq 1 ] || { echo 'Unrelated certificate authority was not rejected correctly.' >&2; exit 1; }
host_ip=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
if [ -n "$host_ip" ]; then
    # Use the valid certificate name while routing to a non-loopback interface.
    # Verification stays enabled, so a certificate mismatch cannot mask exposure.
    set +e
    curl --silent --show-error --fail --noproxy '*' --connect-timeout 2 --max-time 3 --cacert "$artifacts/ca.pem" --resolve "localhost:$port:$host_ip" "https://localhost:$port/readyz" > "$artifacts/non-loopback.out" 2> "$artifacts/non-loopback.err"
    nonloopback_status=$?
    set -e
    case "$nonloopback_status" in
        7|28) echo 'Non-loopback connection blocked as expected.' ;;
        *) echo 'Non-loopback check did not establish the expected network restriction.' >&2; exit 1 ;;
    esac
fi
printf '%s\n' "$before" > "$artifacts/persistent-state.json"
echo 'Container checks passed: HTTPS readiness, certificate rejection, persistent record after restart/replacement, non-root user, read-only root filesystem, and loopback publication.'
