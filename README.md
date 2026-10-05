# Nexus

Nexus is a ledger and messaging/delegation server for agent sessions. Sessions
of one account exchange messages, delegate tasks with scoped, signed
mandates, and ask a person for approval; every message, receipt, delegation
and decision is recorded in a per-session ledger.

**NMCP** exposes Nexus to agents as MCP tools: the same tool contract over a
local stdio MCP server or the remote Streamable HTTP endpoint `/mcp` that
Nexus serves itself (OAuth 2.1). A message from another session is a request,
never authority; only a person widens a delegation.

## Quickstart (self-host)

Requires Docker Engine with Compose v2.

```sh
cd deploy/selfhost
cp .env.example .env && chmod 600 .env   # fill in the values described in the file
docker compose build nexus
docker compose up -d postgres
docker compose run --rm nexus migrate    # before the first start and after every upgrade
docker compose up -d nexus
curl -fsS http://127.0.0.1:8080/v1/health
```

Public HTTPS (Caddy profile), creating the owner, remote MCP, backups and
troubleshooting: [docs/selfhost.md](docs/selfhost.md).

## NMCP

- [docs/nmcp.md](docs/nmcp.md): the tool contract, receipts and client recipes
- [docs/nmcp-remote-endpoint.md](docs/nmcp-remote-endpoint.md): the remote `/mcp` endpoint and OAuth
- [docs/nmcp-delegated-execution.md](docs/nmcp-delegated-execution.md): execution grants
- `conformance/` and `internal/nmcp/conformance_test.go`: conformance tests

## Client

This repository contains the server. The `newtype` client (TUI, CLI and the
stdio MCP server) is distributed as signed binaries from
https://lic.newtype-ai.com/llm.txt.

## Development

```sh
go build ./...
go vet ./...
go test ./...   # PostgreSQL tests skip unless their *_DSN variables point at a disposable database
```

## Status

Early. Interfaces and the schema may change. Security reports:
security@newtype-ai.com (see [SECURITY.md](SECURITY.md)).
<!-- TODO(owner): confirm the security contact address before making this repository public. -->

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
