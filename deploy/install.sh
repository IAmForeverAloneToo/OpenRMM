#!/usr/bin/env bash
# OpenRMM server install: one command on a Linux host that
# already runs Docker with the Compose plugin.
#
#   Public domain (Let's Encrypt, dashboard on port 443):
#     sudo bash install.sh --image IMAGE:VERSION --domain rmm.example.com [--email you@example.com]
#   LAN or lab (the server's own certificate authority):
#     sudo bash install.sh --image IMAGE:VERSION --address 192.168.1.20[,rmm.lan]
#
# Running it again repairs or reconfigures the installation and keeps all
# data (database, keys, certificates and evidence live in Docker volumes).
# Until the first administrator exists, every run prints a new one-time setup
# link (valid 1 hour).
#
# An updater sidecar with access to the Docker socket installs
# signed server releases from the dashboard, with a verified backup and an
# automatic rollback. A later run without --image keeps the version the
# dashboard installed.
set -euo pipefail
umask 077

die() { printf 'openrmm-install: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

usage() {
	cat <<'EOF'
Usage: install.sh [options]
  --image REF            Server image with an exact version (IMAGE:VERSION or IMAGE@sha256:...)
  --domain NAME          Public DNS name; HTTPS certificate from Let's Encrypt (needs port 443 reachable)
  --email ADDRESS        Contact address for Let's Encrypt (optional)
  --address LIST         Comma-separated IP addresses or host names agents and browsers use (LAN installs)
  --dashboard-port N     Dashboard port on this host (default 443; must be 443 with --domain)
  --agent-port N         Agent port on this host (default 8444)
  --dir PATH             Installation folder (default /opt/openrmm)
  --project NAME         Docker Compose project name (default openrmm)
  --acme-directory URL   ACME directory instead of Let's Encrypt (testing)
  --release-key HEX      Extra public key trusted for server releases (your own builds)
  -h, --help             Show this help
Options not given on a later run keep their previous values.
EOF
}

dir=/opt/openrmm
project=openrmm
declare -A arg=()
while [ $# -gt 0 ]; do
	case "$1" in
	-h | --help) usage; exit 0 ;;
	--dir) [ $# -ge 2 ] || die "--dir needs a value"; dir=$2; shift 2 ;;
	--project) [ $# -ge 2 ] || die "--project needs a value"; project=$2; shift 2 ;;
	--image | --domain | --email | --address | --dashboard-port | --agent-port | --acme-directory | --release-key)
		[ $# -ge 2 ] || die "$1 needs a value"
		key=${1#--}
		arg[${key//-/_}]=$2
		shift 2
		;;
	*) die "unknown option $1 (see --help)" ;;
	esac
done

[[ $project =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || die "--project must be lower-case letters, digits, - or _"
[[ $dir = /* && $dir != *[[:space:]]* ]] || die "--dir must be an absolute path without spaces"

# Earlier choices: install.conf holds plain KEY=value lines written by this
# script; only known keys are read, nothing is executed.
image='' domain='' email='' address='' dashboard_port='' agent_port='' acme_directory='' release_key=''
conf=$dir/install.conf
if [ -f "$conf" ]; then
	while IFS='=' read -r key value; do
		case "$key" in
		image | domain | email | address | dashboard_port | agent_port | acme_directory | release_key) printf -v "$key" '%s' "$value" ;;
		esac
	done <"$conf"
fi
# A new --domain or --address replaces the other certificate mode.
if [ -n "${arg[domain]-}" ]; then
	address=''
fi
if [ -n "${arg[address]-}" ]; then
	domain='' email='' acme_directory=''
fi
for key in "${!arg[@]}"; do
	printf -v "$key" '%s' "${arg[$key]}"
done
domain=${domain,,}
domain=${domain%.}
address=${address,,}
address=${address// /}
dashboard_port=${dashboard_port:-443}
agent_port=${agent_port:-8444}

# Docker and Compose must already be installed.
command -v docker >/dev/null 2>&1 || die "Docker is not installed; install Docker Engine first (https://docs.docker.com/engine/install/)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing; install docker-compose-plugin"
docker info >/dev/null 2>&1 || die "cannot reach Docker; run as root (sudo) or as a member of the docker group"
compose() { docker compose --project-name "$project" --project-directory "$dir" -f "$dir/compose.yaml" "$@"; }

# server_container prints the server container's ID, skipping a previous
# version kept during an update from the dashboard.
server_container() {
	docker ps -a --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=server" --format '{{.ID}} {{.Names}}' |
		while read -r id name; do
			case "$name" in *-previous) ;; *) printf '%s\n' "$id" ;; esac
		done | head -n 1
}

# Keep the version the dashboard installed unless --image is given: the
# server container's image, or, after "docker compose down", the image the
# updater recorded as installed.
installed=openrmm-installed-$project:current
if [ -z "${arg[image]-}" ]; then
	running=$(server_container || true)
	current=''
	if [ -n "$running" ]; then
		current=$(docker inspect -f '{{.Config.Image}}' "$running" 2>/dev/null || true)
	elif id=$(docker image inspect -f '{{.Id}}' "$installed" 2>/dev/null); then
		current=$(docker image inspect -f '{{range .RepoTags}}{{println .}}{{end}}' "$id" | grep -v "^openrmm-installed-" | head -n 1 || true)
		[ -n "$current" ] || current=$installed
	fi
	[ -z "$current" ] || image=$current
fi

# Validation (the server checks the same values again).
[ -n "$image" ] || die "--image is required on the first run (an exact version, for example openrmm/server:0.6.0)"
[[ $image =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$ ]] || die "--image is not a valid image reference"
last=${image##*/}
if [[ $image != *@sha256:* ]] && { [[ $last != *:* ]] || [[ $last == *:latest ]]; }; then
	die "--image needs an exact version or digest, not a floating tag"
fi
[ -n "$domain" ] || [ -n "$address" ] || die "give --domain (public name) or --address (LAN)"
[ -z "$domain" ] || [ -z "$address" ] || die "give either --domain or --address, not both"
for port in "$dashboard_port" "$agent_port"; do
	[[ $port =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "ports must be numbers from 1 to 65535"
done
[ "$dashboard_port" != "$agent_port" ] || die "the dashboard and agent ports must differ"
if [ -n "$domain" ]; then
	[[ $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "--domain must be a DNS name such as rmm.example.com"
	[ "$dashboard_port" = 443 ] || die "with --domain the dashboard must use port 443 (Let's Encrypt validates there)"
	[ -z "$email" ] || [[ $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || die "--email must be an email address"
	[ -z "$acme_directory" ] || [[ $acme_directory =~ ^https://[A-Za-z0-9.:/_~%?=\&-]+$ ]] || die "--acme-directory must be an https URL"
	public=$domain
else
	[[ $address =~ ^[a-z0-9.:-]+(,[a-z0-9.:-]+)*$ ]] || die "--address must be IP addresses or host names separated by commas"
	public=${address%%,*}
	[[ $public != *:* ]] || public="[$public]"
fi
server_url=https://$public
[ "$dashboard_port" = 443 ] || server_url=$server_url:$dashboard_port
device_url=https://$public:$agent_port

[ -z "$release_key" ] || [[ $release_key =~ ^[0-9a-f]{64}$ ]] || die "--release-key must be a 64-character hex public key"

# The updater reaches Docker through its socket; without one (for example
# rootless Docker) the server is installed without updates from the dashboard.
socket=/var/run/docker.sock
socket_gid=''
if [ -S "$socket" ]; then
	socket_gid=$(stat -c %g "$socket")
else
	say "Note: $socket was not found; updates from the dashboard are unavailable (run this command again to update)."
fi

if [ ! -d "$dir" ]; then
	mkdir -p "$dir"
	chmod 700 "$dir"
fi
write() { # write PATH: stdin to PATH, replaced in one step
	cat >"$1.tmp"
	chmod 600 "$1.tmp"
	mv -f "$1.tmp" "$1"
}

write "$conf" <<EOF
image=$image
domain=$domain
email=$email
address=$address
dashboard_port=$dashboard_port
agent_port=$agent_port
acme_directory=$acme_directory
release_key=$release_key
EOF

{
	cat <<EOF
# Written by install.sh; run it again to change these.
OPENRMM_SERVER_LISTEN=0.0.0.0:8443
OPENRMM_SERVER_DEVICE_LISTEN=0.0.0.0:8444
OPENRMM_SERVER_CONTAINER_NETWORK=true
OPENRMM_SERVER_DATABASE=/data/openrmm.db
OPENRMM_SERVER_ENCRYPTION_KEY=/secrets/admin-key.bin
OPENRMM_SERVER_DEVICE_AUTHORITY=/secrets/device-ca/authority.pem
OPENRMM_SERVER_EVIDENCE_DIR=/evidence
OPENRMM_SERVER_PUBLIC_URL=$server_url
OPENRMM_SERVER_PUBLIC_DEVICE_URL=$device_url
OPENRMM_LOG_LEVEL=info
EOF
	[ -z "$socket_gid" ] || say "OPENRMM_SERVER_UPDATER_DIR=/updater"
	[ -z "$release_key" ] || say "OPENRMM_SERVER_RELEASE_KEYS=$release_key"
	if [ -n "$domain" ]; then
		say "OPENRMM_SERVER_ACME_DOMAIN=$domain"
		[ -z "$email" ] || say "OPENRMM_SERVER_ACME_EMAIL=$email"
		[ -z "$acme_directory" ] || say "OPENRMM_SERVER_ACME_DIRECTORY=$acme_directory"
	else
		say "OPENRMM_SERVER_HOSTS=$address"
	fi
} | write "$dir/server.env"

{
	cat <<EOF
# Written by install.sh; run it again to change it. Data lives in the
# volumes and is kept when the server is recreated.
name: $project

services:
  server:
    image: $image
    restart: unless-stopped
    env_file: [server.env]
    ports:
      - "$dashboard_port:8443"
      - "$agent_port:8444"
    volumes:
      - data:/data
      - secrets:/secrets
      - evidence:/evidence
      - updater:/updater
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 256
    mem_limit: 1g
    stop_grace_period: 15s
    healthcheck:
      test: [CMD, /openrmm-server, -health]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
	if [ -n "$socket_gid" ]; then
		cat <<EOF

  # Installs signed releases from the dashboard. It has no
  # network and no port; it reads requests from the updater volume.
  updater:
    image: $image
    entrypoint: [/openrmm-updater]
    restart: unless-stopped
    environment:
      OPENRMM_UPDATER_PROJECT: $project
      OPENRMM_UPDATER_KEYS: "$release_key"
    group_add: ["$socket_gid"]
    network_mode: none
    volumes:
      - $socket:/var/run/docker.sock
      - updater:/updater
      - backups:/backups
      - data:/data
      - secrets:/secrets
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 256m
    logging:
      driver: json-file
      options:
        max-size: "5m"
        max-file: "2"
EOF
	fi
	cat <<EOF

volumes:
  data:
  secrets:
  evidence:
  updater:
  backups:
EOF
} | write "$dir/compose.yaml"

say "Starting OpenRMM ($image) ..."
if ! output=$(compose up -d --remove-orphans 2>&1); then
	printf '%s\n' "$output" >&2
	die "Docker Compose could not start the server"
fi

# Wait until the server reports ready (a first Let's Encrypt certificate can
# take a minute).
status=starting
for _ in $(seq 1 60); do
	container=$(server_container || true)
	status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || echo starting)
	[ "$status" = healthy ] && break
	if compose exec -T server /openrmm-server -health >/dev/null 2>&1; then
		status=healthy
		break
	fi
	# A server that exits at start (for example on a bad setting) restarts
	# over and over; stop waiting once it has.
	restarts=$(docker inspect -f '{{.RestartCount}}' "$container" 2>/dev/null || echo 0)
	[ "$restarts" -lt 2 ] || break
	sleep 5
done
if [ "$status" != healthy ]; then
	compose logs --tail 30 server >&2 || true
	die "the server did not become ready; see the log above, fix the cause and run this command again"
fi

# Record the installed image, so a later run after "docker compose down" keeps
# it (the updater moves this tag when it installs a release).
docker tag "$(docker inspect -f '{{.Image}}' "$container")" "$installed" >/dev/null 2>&1 || true

say ""
say "OpenRMM is running."
say "  Dashboard:     $server_url"
say "  Agent address: $device_url"
say "  Settings:      $dir (compose.yaml, server.env)"
if [ -z "$domain" ]; then
	say "  Certificate:   from this server's own authority; browsers warn until you trust it,"
	say "                 agents installed from the dashboard trust it automatically."
fi

# The first administrator is created in the browser from a one-time link.
if result=$(compose exec -T server /openrmm-server -admin-link 2>&1); then
	token=$(printf '%s' "$result" | sed -n 's/.*"token":"\([A-Za-z0-9_-]*\)".*/\1/p')
	[ -n "$token" ] || die "could not read the setup link"
	say ""
	say "Create the first administrator within one hour (the link works once):"
	say "  $server_url/setup#$token"
	say "Run this command again for a new link."
elif printf '%s' "$result" | grep -q 'already configured'; then
	say ""
	say "An administrator exists; sign in at $server_url"
else
	printf '%s\n' "$result" >&2
	die "could not create the setup link"
fi
