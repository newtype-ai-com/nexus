# nexus/httpapi

Package `httpapi` is the HTTP adapter for the Nexus ledger (`nexus.Service`).
It turns authenticated HTTP requests into ledger operations and serves the
results as JSON and server-sent events. It does not authenticate anyone itself:
the caller injects an `Authenticator` that returns a trusted
`nexus.Principal`, and identity is never taken from request bodies or headers
such as account or session fields.

## Entry points

- `New(Config) (*API, error)` builds the handler. `Config` takes the
  `*nexus.Service`, the `Authenticate` (and optional `Reauthenticate`)
  functions, and a runner (`Run`, or `RunMetered` in durable mode).
  `internal/nexusserver` wires it into the `nexus serve` process.
- `NewCoreRunner` / `NewMeteredCoreRunner` run a model turn through `core`
  for an execution. A runner receives no tools, secrets or client-supplied
  capabilities; an approval covers one exact model input only.

## Routes (summary)

- Delegations: `POST /v1/delegations`, `GET /v1/delegations/{id}`,
  `GET /v1/delegations/{id}/left`, `POST /v1/delegations/{id}/revoke`,
  root issuance via `POST /v1/requests` and `POST /v1/observers`.
- Executions: `POST|GET /v1/executions/{id}`, `.../approval`, `.../cancel`.
  Durable mode keeps approvals and results in the ledger so they survive a
  restart or a replica change; results and events are status-only and never
  carry credentials, arguments or runner output.
- Messages and inbox: `POST /v1/messages`, `POST /v1/messages/delivered`,
  `POST /v1/messages/read`, `GET /v1/messages/{id}`, `GET /v1/inbox`.
  Delivery and read receipts are idempotent ledger events.
- Sessions: `GET|POST /v1/sessions/{session}/events`,
  `GET /v1/sessions/{session}/stream` (SSE with a resumable cursor),
  `POST /v1/sessions/{session}/credentials`.
- Execution grants, custody approvals, secrets (`/v1/secrets`), teams and
  `GET /v1/accounts/self`.

## Testing

Tests use an in-memory store, a fake model and synthetic credentials, and run
with no network or external service:

```sh
go test ./nexus/httpapi
```

The PostgreSQL store (`nexus/pgstore`) and `conformance` suites run the same
ledger contracts against a real database when `NTS_NEXUS_TEST_DSN` points at a
disposable PostgreSQL database; without it those tests are skipped, which does
not count as database verification:

```sh
NTS_NEXUS_TEST_DSN=postgres://... go test -race ./nexus/... ./conformance
```
