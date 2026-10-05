# Minimal Nexus image. Build from the repository root:
#   docker build -f deploy/Dockerfile -t nexus:local .
# For a full self-host setup use deploy/selfhost (compose, Caddy, Postgres).
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# deploy/Dockerfile.dockerignore limits the context to the packages cmd/nexus needs.
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /nexus ./cmd/nexus

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /nexus /nexus
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/nexus"]
