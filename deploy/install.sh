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
# automatic rollback, and takes a verified backup every night. A later run
# without --image keeps the version the dashboard installed.
#
# Backups and restores:
#   sudo bash install.sh backup [--evidence]
#   sudo bash install.sh restore NAME|FILE
set -euo pipefail
umask 077

die() { printf 'openrmm-install: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

usage() {
	cat <<'EOF'
Usage: install.sh [options]              install, repair or reconfigure
       install.sh backup [--evidence]    take a backup now and save it under DIR/backups
       install.sh backups                list the backups
       install.sh restore NAME|FILE [--revocations FILE] [--skip-safety-backup]
                                         restore a backup (stops the server for the restore)
       install.sh restore-evidence [FILE...]
                                         add exported case evidence back (default: all under DIR/backups/evidence)
Install options:
  --image REF            Server image with an exact version (IMAGE:VERSION or IMAGE@sha256:...);
                         default: the latest published release
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
Backup and restore options:
  --evidence             Also export case evidence added since the last export (can be large)
  --revocations FILE     Reviewed revocation list, when the current server is lost (see the recovery guide)
  --skip-safety-backup   Restore without first backing up the current state (for a damaged database)
--dir and --project select the installation as above.
EOF
}

# Published releases: GitHub releases of this repository, images on GHCR.
release_repository=IAmForeverAloneToo/OpenRMM
release_image=ghcr.io/iamforeveralonetoo/openrmm-server

dir=/opt/openrmm
project=openrmm
action=install
case "${1-}" in
backup | backups | restore | restore-evidence) action=$1; shift ;;
esac
declare -A arg=()
evidence='' revocations='' skip_safety='' targets=()
while [ $# -gt 0 ]; do
	case "$1" in
	-h | --help) usage; exit 0 ;;
	--dir) [ $# -ge 2 ] || die "--dir needs a value"; dir=$2; shift 2 ;;
	--project) [ $# -ge 2 ] || die "--project needs a value"; project=$2; shift 2 ;;
	--image | --domain | --email | --address | --dashboard-port | --agent-port | --acme-directory | --release-key)
		[ "$action" = install ] || die "$1 is an install option (see --help)"
		[ $# -ge 2 ] || die "$1 needs a value"
		key=${1#--}
		arg[${key//-/_}]=$2
		shift 2
		;;
	--evidence) [ "$action" = backup ] || die "--evidence goes with backup"; evidence=1; shift ;;
	--revocations) [ "$action" = restore ] && [ $# -ge 2 ] || die "--revocations goes with restore and needs a file"; revocations=$2; shift 2 ;;
	--skip-safety-backup) [ "$action" = restore ] || die "--skip-safety-backup goes with restore"; skip_safety=1; shift ;;
	-*) die "unknown option $1 (see --help)" ;;
	*) [ "$action" = restore ] || [ "$action" = restore-evidence ] || die "unexpected argument $1 (see --help)"; targets+=("$1"); shift ;;
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

# wait_ready waits until the server reports ready (a first Let's Encrypt
# certificate can take a minute) and shows its log if it does not.
wait_ready() {
	local status=starting restarts
	for _ in $(seq 1 60); do
		container=$(server_container || true)
		status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || echo starting)
		[ "$status" = healthy ] && return 0
		if compose exec -T server /openrmm-server -health >/dev/null 2>&1; then
			return 0
		fi
		# A server that exits at start (for example on a bad setting) restarts
		# over and over; stop waiting once it has.
		restarts=$(docker inspect -f '{{.RestartCount}}' "$container" 2>/dev/null || echo 0)
		[ "$restarts" -lt 2 ] || break
		sleep 5
	done
	compose logs --tail 30 server >&2 || true
	return 1
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

# Backups and restores run the updater's backup tool in a one-off container
# with the installation's volumes and no network; it runs as the server's
# user, so restored files keep the right owner.
if [ "$action" != install ]; then
	[ -f "$conf" ] && [ -n "$image" ] || die "no OpenRMM installation found in $dir (see --dir and --project)"
	backups=$dir/backups
	tool() { # tool [docker run options --] COMMAND...: run the backup tool
		local extra=()
		while [ $# -gt 0 ] && [ "$1" != -- ]; do extra+=("$1"); shift; done
		[ "${1-}" != -- ] || shift
		docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true -e SQLITE_TMPDIR=/backups \
			-v "${project}_data:/data" -v "${project}_secrets:/secrets" -v "${project}_backups:/backups" "${extra[@]}" \
			--entrypoint /openrmm-updater "$image" "$@"
	}
	save() { # save PATH COMMAND...: the command's output to PATH, kept only when complete
		local path=$1
		shift
		if "$@" >"$path.part"; then
			mv -f "$path.part" "$path"
		else
			rm -f "$path.part"
			return 1
		fi
	}
	start() { # start the server again and wait until it is ready
		if ! output=$(compose up -d 2>&1); then
			printf '%s\n' "$output" >&2
			die "Docker Compose could not start the server"
		fi
		wait_ready || die "the server did not become ready after the restore; see the log above"
	}
	mkdir -p "$backups"
	chmod 700 "$backups"
	case "$action" in
	backups)
		say "Backups on this server (in the ${project}_backups volume):"
		tool -- list
		say ""
		say "Exported backups in $backups:"
		ls -1 "$backups" | grep '\.tar\.gz$' || say "  (none)"
		;;
	backup)
		say "Taking a backup (the server keeps running) ..."
		name=$(tool -- backup) || die "the backup failed"
		save "$backups/$name.tar.gz" tool -- export "$name" || die "the backup $name could not be saved to $backups"
		say "Backup $name saved to $backups/$name.tar.gz"
		if [ -n "$evidence" ]; then
			mkdir -p "$backups/evidence"
			since=$(cat "$backups/evidence/.since" 2>/dev/null || echo 0)
			[[ $since =~ ^[0-9]+$ ]] || since=0
			now=$(date +%s)
			file=$backups/evidence/evidence-$(date -u +%Y%m%d-%H%M%S).tar
			say "Exporting case evidence added since the last export ..."
			save "$file" tool -v "${project}_evidence:/evidence:ro" -- export-evidence --since "$since" || die "the evidence export failed"
			printf '%s\n' "$now" >"$backups/evidence/.since"
			# An empty tar archive is 1 KiB or less.
			if [ "$(stat -c %s "$file")" -le 1024 ]; then
				rm -f "$file"
			else
				say "Evidence saved to $file"
			fi
		fi
		say "Copy $backups to separate, protected storage: it holds the server's keys."
		;;
	restore)
		[ ${#targets[@]} -eq 1 ] || die "restore needs one backup name or file (see: install.sh backups)"
		target=${targets[0]}
		[ -z "$revocations" ] || [ -f "$revocations" ] || die "the revocation list $revocations was not found"
		if [ -f "$target" ]; then
			say "Importing $target ..."
			name=$(tool -- import <"$target") || die "the backup file could not be imported"
		else
			name=$target
		fi
		[[ $name =~ ^(update|nightly|manual|pre-restore)-[0-9]{8}-[0-9]{6}(-[0-9]{1,5})?$ ]] || die "$name is not a backup name (see: install.sh backups)"
		options=()
		[ -z "$skip_safety" ] || options+=(--skip-safety-backup)
		[ -z "$revocations" ] || options+=(--revocations-stdin)
		say "Stopping OpenRMM to restore $name ..."
		compose stop >/dev/null 2>&1 || die "the server could not be stopped"
		if tool -- restore "$name" "${options[@]}" <"${revocations:-/dev/null}"; then
			say "Starting the restored server ..."
			start
			say ""
			say "Restored $name. Sign in again with a fresh authenticator code, review technician accounts"
			say "(they were disabled) and resume alert e-mail in Alert settings."
		else
			say "The restore failed; starting the server again ..."
			start
			die "the restore failed (see the message above)"
		fi
		;;
	restore-evidence)
		files=("${targets[@]}")
		if [ ${#files[@]} -eq 0 ]; then
			shopt -s nullglob
			files=("$backups"/evidence/evidence-*.tar)
		fi
		[ ${#files[@]} -gt 0 ] || die "no evidence exports found in $backups/evidence"
		for file in "${files[@]}"; do
			[ -f "$file" ] || die "$file was not found"
			say "Adding evidence from $file ..."
			tool -v "${project}_evidence:/evidence" -- import-evidence <"$file" || die "$file could not be imported"
		done
		;;
	esac
	exit 0
fi

# A first install without --image uses the latest published release, pinned
# to its exact version.
if [ -z "$image" ]; then
	command -v curl >/dev/null 2>&1 || die "curl is needed to find the latest release; install curl or pass --image"
	latest=$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$release_repository/releases/latest" |
		sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"v\([0-9][0-9.]*[0-9A-Za-z.-]*\)".*/\1/p' | head -n 1) || true
	[ -n "$latest" ] || die "cannot find the latest release; check the network or pass --image"
	image="$release_image:$latest"
	say "Using the latest release: $image"
fi

# Validation (the server checks the same values again).
[ -n "$image" ] || die "--image is required (an exact version, for example $release_image:0.1.0)"
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
      SQLITE_TMPDIR: /backups
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
wait_ready || die "the server did not become ready; see the log above, fix the cause and run this command again"

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
