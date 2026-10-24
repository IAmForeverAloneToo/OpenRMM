#!/bin/sh
# Run in WSL/Linux after building the Windows executables. The pinned scanner
# stays in a disposable development container, outside the application graph.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
for program in server agent devcert desktop release; do
    [ -f "dist/windows-amd64/openrmm-$program.exe" ] || { echo 'Build Windows binaries first.' >&2; exit 1; }
done
docker build --target build -t openrmm-build:dev .
docker run --rm \
    --mount "type=bind,src=$project_root/dist/windows-amd64,dst=/checks,readonly" \
    -e GOTELEMETRY=off -e CGO_ENABLED=0 -e GOWORK=off \
    openrmm-build:dev sh -ec '
        go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
        export GOFLAGS=-mod=readonly
        govulncheck -show verbose ./...
        GOOS=windows govulncheck -show verbose ./...
        govulncheck -mode binary /out/openrmm-server
        for program in server agent devcert desktop release; do
            govulncheck -mode binary "/checks/openrmm-$program.exe"
        done
    '
