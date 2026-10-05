# Self-host Nexus image. Build from the repository root:
#   docker build -f deploy/selfhost/Dockerfile -t newtype-nexus:local .
# (docker compose in this directory does the same.) The build context is
# limited by Dockerfile.dockerignore next to this file (BuildKit).
FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /nexus ./cmd/nexus
# An empty /data owned by the runtime uid: a new named volume mounted there
# copies this ownership, so uid 65532 can write it (distroless has no shell).
RUN mkdir -p /out/data

# distroless/static: CA certificates, no shell, runs as 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /nexus /nexus
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/nexus"]
CMD ["serve"]
