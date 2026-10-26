# The web dashboard is built here, so an image built from a clean checkout
# always embeds it. Node exists only in this build stage, never in the image.
FROM node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci --ignore-scripts --no-fund --loglevel=error
COPY web/ ./
# "build" typechecks first, then writes ../internal/server/webui/dist.
RUN --network=none npm run --silent build

FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
ENV GOWORK=off
COPY go.mod go.sum dependencies.lock ./
RUN go mod download \
    && go list -mod=readonly -m all > /tmp/resolved-modules \
    && diff -u dependencies.lock /tmp/resolved-modules \
    && go mod verify
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web /src/internal/server/webui/dist/ ./internal/server/webui/dist/
RUN --network=none CGO_ENABLED=0 go test -mod=readonly ./... \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/openrmm-server ./cmd/openrmm-server \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/openrmm-agent ./cmd/openrmm-agent \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/openrmm-devcert ./cmd/openrmm-devcert \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/openrmm-updater ./cmd/openrmm-updater \
    && install -d -m 0700 -o 10001 -g 10001 /runtime/data /runtime/tls /runtime/secrets /runtime/evidence /runtime/backups /runtime/updater

FROM scratch
COPY THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
COPY LICENSE NOTICE /
# Public TLS roots from the already pinned builder image; no package installation.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /
COPY --from=build --chown=10001:10001 /runtime/ /
USER 10001:10001
EXPOSE 8443 8444
ENTRYPOINT ["/openrmm-server"]
