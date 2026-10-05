# NMCP stage 5 — The remote MCP endpoint served by Nexus (design, 2026-10-04)

Status: **implemented** — §9.

Notation: `https://nexus.example.com` below is the public origin of the Nexus configured with `NEXUS_MCP_ISSUER` (on the hosted service, `https://lic.newtype-ai.com`).

Goal: without any install, MCP clients (claude.ai connectors, Claude Code `--transport http`, other hosts) connect to `https://nexus.example.com/mcp` and use **the same contract** as the local `newtype nmcp serve` (`nexusops.Defs`, same semantics, same receipt rules). This document is the design, and the implementation follows it.

## 0. Principles

1. **The token says "may connect"; the delegation says "may act".** The OAuth access token only proves that a person allowed this client to connect to this account. Whether each tool call is allowed or refused is always decided by the Nexus session delegation of that connection (`delegation_info`, policy auto/ask/deny, limits, expiry). Token scopes cannot widen a delegation.
2. **Same contract, same code.** The remote endpoint uses `internal/nmcp.Server` as is and changes only the transport (stdio lines ↔ Streamable HTTP). Tool definitions, instructions, annotations, Tasks, elicitation, subscriptions and receipt rules live in one place.
3. **No token passthrough.** Tokens for `/mcp` are accepted only at `/mcp` (audience = `https://nexus.example.com/mcp`). `/v1/*` does not accept them, and the server never forwards them anywhere. Tokens for other servers (other audiences) are refused.
4. **Only people widen authority.** Approval requests from remote clients go to a person through elicitation → (if unanswered) mail approval. Approval on any path never widens the Nexus delegation (same as local).
5. **Everything is in the ledger.** Connections, token issuance, revocations, tool calls and approvals are recorded in the account ledger (or the connection session's ledger), and each record states who acted on behalf of whom (the actor chain, §6).

## 1. Transport — Streamable HTTP (MCP 2025-06-18 / 2025-11-25)

Path: `POST|GET|DELETE /mcp` (`nexus serve`). Supported versions are the same list as local.

- **POST /mcp**: the body is a single JSON-RPC message (no batches, same as local). `Accept` must include both `application/json` and `text/event-stream`.
  - For a request: answer with SSE (`text/event-stream`) until that request's response is produced. Requests and notifications the server sends in the meantime (for example `elicitation/create`, `notifications/progress`) travel on the same stream. The stream closes once the response is written. Requests that finish immediately (`initialize`, `tools/list`, `ping`) may be answered with a single `application/json`.
  - For a notification or a response (the client answering our `elicitation/create`): `202 Accepted`, no body.
- **GET /mcp**: a standalone server→client stream (SSE). Notifications unrelated to a request (`notifications/resources/updated`) and server requests sent while no POST stream is open travel here. One per session. `: heartbeat` every 30 seconds.
- **DELETE /mcp**: ends the session. In-flight calls are cancelled (no response, no read, same as local), and watchers stop.
- **Session**: the `Mcp-Session-Id` header in the `initialize` response (unguessable 256 bits, the key of the in-memory connection table). Every later request must send this header and `MCP-Protocol-Version`. Unknown sessions get `404` (the client re-initializes). A session is **bound to the token's (account, client_id)**: using the same session ID with a different token gets `404`.
- **Resumption**: SSE events carry an `id`, and a GET stream reopened with `Last-Event-ID` receives the missed notifications again (the latest 256 per session, in memory). POST streams are not resumed (a dropped one counts as cancellation of that call: no response or receipt; a write tool with an unknown outcome has the same `cancelled` meaning as local).
- **Security headers**: if `Origin` is present, only the allow list (`https://claude.ai`, `https://nexus.example.com`, configured values). If absent (server-to-server clients), pass. Request body 4 MiB, 16 sessions per account, 1024 overall, cleaned up after 30 minutes idle.
- **Implementation (adapter)**: each connection runs one `nmcp.Server` over an in-memory pipe. The POST body is written as one line to that server's input, and output lines are read: a response with the same id as the POST is written to that POST stream, which then closes; server requests and notifications go to the in-flight POST stream if there is one, otherwise to the GET stream (or the resumption buffer). The server-side code does not differ from stdio by a single character.

## 2. Authentication — OAuth 2.1 protected resource server (MCP authorization spec)

The Nexus server is a **protected resource server** and, at this stage, also the **authorization server** in the same process (paths and storage are kept separate so they can be split later).

### 2.1 Discovery

- `401` response: `WWW-Authenticate: Bearer resource_metadata="https://nexus.example.com/.well-known/oauth-protected-resource/mcp", scope="nexus:connect"`. With a token that is insufficient: `403` + `error="insufficient_scope"`.
- `GET /.well-known/oauth-protected-resource/mcp` (RFC 9728; the path-suffixed form is preferred, and the root `/.well-known/oauth-protected-resource` serves the same document):
  `{"resource":"https://nexus.example.com/mcp","authorization_servers":["https://nexus.example.com"],"scopes_supported":["nexus:connect"],"bearer_methods_supported":["header"],"resource_name":"Newtype Nexus"}`
- `GET /.well-known/oauth-authorization-server` (RFC 8414): `issuer`, `authorization_endpoint` `/oauth/authorize`, `token_endpoint` `/oauth/token`, `registration_endpoint` `/oauth/register`, `revocation_endpoint` `/oauth/revoke`, `response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token"]`, `code_challenge_methods_supported:["S256"]`, `token_endpoint_auth_methods_supported:["none"]` (public clients, PKCE required), `client_id_metadata_document_supported:false` (first phase; §2.6).

### 2.2 Client registration

- **Dynamic registration** (RFC 7591) `POST /oauth/register`: `client_name`, `redirect_uris` (https, or loopback `http://127.0.0.1:*`/`http://localhost:*` only; exact-match comparison), `grant_types`, `token_endpoint_auth_method:"none"`. Result: `client_id` (`mcl_…`). No secret is issued. Registration alone grants nothing (there is no token before a person consents). Abuse controls: per-IP and global registration rate limits, and registrations unused for 90 days are cleaned up.
- Registration records do not belong to an account (public clients owned by no one). Consent links an account and a client_id.

### 2.3 Authorization — how a person allows a client

`GET /oauth/authorize?response_type=code&client_id&redirect_uri&code_challenge&code_challenge_method=S256&state&scope=nexus:connect&resource=https://nexus.example.com/mcp`

- `resource` (RFC 8707) is required and must be exactly `https://nexus.example.com/mcp`; otherwise `invalid_target`. `redirect_uri` must exactly match the registered value; if it does not, show an error page instead of redirecting.
- **Human confirmation (first phase: built on the existing login)**: the consent page shows "Client *client_name* (redirect host shown) wants to connect to your Nexus account · connecting creates a session for this client, and that session receives only a tool-only delegation (no model, one level of `session:delegate`)", and confirmation happens in one of two ways.
  1. **Email confirmation**: "Send confirmation mail" on the consent page → Nexus creates an `mcp_connect` change request at the approval server (admin client) → the approval server sends a one-time link to the **owner address** (`NEXUS_OWNER_EMAIL`) → the person approves at the link → the consent page's polling sees the approval and calls `Consume` (once) → creates the consent for the account of that address (exactly one in `gate_credentials`/`gate_accounts`) and redirects to `redirect_uri?code&state&iss`. Because the approval server mails only the owner, mail confirmation is for the owner account only (same as the owner-only policy).
  2. **CLI confirmation**: an 8-character user code on the page → a person with a live login runs `newtype nmcp authorize CODE` (the same shape as the existing device flow `/v1/device`) → the page proceeds.
  - Both use **existing login and mail paths**. No password entry.
  - The page sends `X-Frame-Options: DENY`, CSP (`script-src 'self'`, `frame-ancestors 'none'`) and `no-store`. Opening the page alone allows nothing. Pending requests last 15 minutes, at most 256 (in memory).
  - **Later (passkeys)**: confirm directly on the consent page with a WebAuthn assertion (the account root passkey). Once there is a passkey domain, this replaces 1 and 2 (the same key as the client's passkey design; client, not in this repository).
- Code: `mca_…`, single use, 60 seconds, PKCE `S256` verified, bound to client_id, redirect_uri and resource. Using it twice revokes every token issued with that code (as recommended by RFC 6749 §4.1.2).

### 2.4 Tokens

- `POST /oauth/token` `grant_type=authorization_code` (+`code_verifier`, `redirect_uri`, `client_id`, `resource`) → `{"access_token":"ntm_…","token_type":"Bearer","expires_in":3600,"refresh_token":"ntr_…","scope":"nexus:connect"}`.
- **Opaque tokens**; the server stores only a SHA-256 verifier (the same scheme as gate credentials). Recorded: verifier, kind (access/refresh), client_id, account, email, **audience = `https://nexus.example.com/mcp`**, scope, consent ID, expiry, revocation.
- Access tokens last 1 hour; refresh tokens 30 days with rotation (a new refresh token on every use). Reusing a rotated old refresh token is treated as theft and **revokes the consent itself** (all tokens invalid; the person must allow again).
- Revocation: `POST /oauth/revoke` (RFC 7009); on the person's side `newtype nmcp clients` / `newtype nmcp revoke CLIENT` (list and revoke consents); and revocation together with the account's login.
- **Checks (every `/mcp` request)**: exactly one Bearer, `ntm_` prefix, verifier lookup, kind access, not revoked, not expired, **audience exactly equal**, `nexus:connect` in scope, consent not revoked. Any failure gives `401` (+`WWW-Authenticate`). Tokens in query strings are not accepted.
- `/v1/*` authentication (`executorOrGate` → gate) **refuses** `ntm_`/`ntr_` (401 immediately by prefix). Conversely, `/mcp` refuses licence, login, agent and executor tokens.
- Storage: new tables `mcp_oauth_clients`, `mcp_oauth_consents`, `mcp_oauth_codes`, `mcp_oauth_tokens` (in Nexus's Postgres, using the existing `gate_meta` versioned migration scheme). The `gate_credentials.kind` CHECK is not changed (to keep these apart from login credentials). An in-memory implementation for tests.

### 2.5 Connection → session → delegation

- On the first `initialize`, a **connection session** is found or created from (account, client_id, `clientInfo.name`): title `mcp:<client_name>` (so a person recognizes it in `nexus peers`), with a new runner **`remote`**, distinct from runner `local` (an MCP connection run by the Nexus server on the client's behalf; neither a container nor a person's terminal). One session per consent (several MCP sessions of the same client share the same Nexus session, and share its inbox).
- Root delegation: the same as the local `nmcpRoot` — the single scope `session:delegate`, 0 model tokens, `max_depth` 1, 8 hours, person = the consenting account's person. When it expires, it is reissued on the next `initialize` (as long as the consent is alive).
- Tool calls run as this session principal (`SessionPrincipal(account, session)`). **Decisions are the server's delegation checks** (the same `nexus.Service` path as local); the token takes no part.
- **In-process calls (no token)**: `nexusops.Seat` uses an HTTP client, so inside the server `nexustransport.Client.WithTransport` is given an **in-process RoundTripper**. This RoundTripper puts the verified principal in the request context and calls the server's `http.Handler` directly. The front of `executorOrGate` looks at the principal in the context first (network requests cannot carry Go context values) and falls back to header authentication only when there is none. So the authorization, limit and ledger code of `/v1/*` runs unchanged, and OAuth tokens never flow into `/v1/*` (principle 3). `Reauthenticate` (streams) looks at the same context principal, and when the consent or token is revoked, that session is dropped from the connection table and its streams end.
- The gate's session check (which allows only `Local`) is not touched so that session principals can have the `remote` runner: in-process principals do not go through header authentication, so it is not needed. In turn, a `remote` session can never be authenticated by headers (using a `remote` session with licence+login+`X-Newtype-Session` gives 401 — the current code already allows only `Local`).

## 3. Same semantics (same as local)

- Instructions (KO+EN), annotations, the `nexus_inbox` wait (the same maximum of 600 seconds as local; long calls open the POST SSE immediately and send `: heartbeat` every 30 seconds so that proxy idle limits, for example 100 seconds, do not cut them), Tasks (for the lifetime of the connection session's memory), elicitation (if the client declares it), `nexus://inbox` and `nexus://tasks/{id}` subscriptions with receipt-free notifications — all `nmcp.Server` as is.
- Read = after the result has been written to the client. Remotely, that means "after the response SSE event has been written and the flush succeeded". On a write failure or a dropped connection, no read.
- `claude/channel` is not declared remotely (Claude Code channels are for stdio subprocesses only).
- `tool.call` records go to the connection session's ledger, with the actor chain of §6 attached.

## 4. Approval — elicitation, and mail when nobody answers

The `request_approval` path (there is always exactly one decision):

1. The server already allows it (auto) → allowed.
2. An action the person approved "for this session" on this connection → approved.
3. The client declared elicitation → `elicitation/create`, **at most 2 minutes**. If the person answers, that result (once/session/deny), ledger `tool.approval decided_by person:mcp-elicitation`.
4. No elicitation, no answer within 2 minutes, or `cancel` → **mail approval** (server side, using the approval server admin token held by the Nexus server):
   - The Nexus server creates a request of the new kind `mcp_approval` at the approval server through the same admin path as `gate.ChangeAdminClient.Begin` (`POST /v1/changes`; content: account, connection session, client_name, action, reason summary up to 2000 characters, 15-minute expiry). The approval server sends a link to the account's email (currently the owner only). The link page reuses the existing approval page (approve/deny). Therefore **mail approval is always "just this once"**; "for this session" can only be chosen through elicitation.
   - Waiting: `request_approval` called through Tasks returns a task handle immediately and waits for the mail result (`tasks/result`). Without Tasks, `request_approval` waits for `wait_seconds` (default 0, maximum 300) and, if no decision has been made, returns `{"status":"pending","via":"mail","approval_id":…}`. Calling again with the same `action` and `reason` checks the status of the same request without new mail (request key = connection session + action + reason).
   - The result is taken once with `Consume`, recorded in the ledger as `tool.approval decided_by person:mail`, and, if "for this session", added to the connection's in-process approval table.
   - The admin token exists only in the Nexus server's private environment file and appears nowhere in tool results, logs or the ledger. The approval server's `/v1/changes` is not exposed through the public proxy (no external access).
5. Elicitation declined (`decline`/`deny`) → denied, with no fallback to mail (the person has already answered).

The local `newtype nmcp serve` has no admin token, so instead of step 4 it keeps using the operator-seat message. If mail is wanted locally later, a new Nexus path (`POST /v1/approvals/mail`, called by the session principal, with Nexus making the approval server request on its behalf) can be used, and even then the admin token never leaves Nexus.

## 5. Public proxy and SSE

- `/mcp`, `/.well-known/oauth-*` and `/oauth/*` go to the same Nexus server as `/v1/*`. The approval server admin path (`/v1/changes`) and `/metrics` are not exposed.
- The proxy must not buffer streams (the selfhost Caddy uses `flush_interval -1`). For proxies with idle limits, the 30-second heartbeat is enough (for example a 100-second limit).
- Checks after deployment:
  1. With `curl -N -H 'Accept: text/event-stream' …/v1/sessions/<id>/stream` (the existing stream), `: connected` and the 30-second `: heartbeat` arrive without delay (no buffering), and the stream ends cleanly at the end of its 4-minute lifetime.
  2. While receiving `nexus_inbox wait_seconds:120` as SSE through a `/mcp` POST, a message sent by another session produces the response event immediately.
  3. A GET `/mcp` stream kept open for 10 minutes is not cut, thanks to the heartbeat.
  - Server side: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`, no compression, flush on every event (the same as the existing `stream` handler).

## 6. Actor chain — review of RFC 8693 `act`

The `act` claim of RFC 8693 (token exchange) records "an actor (act.sub) acts on behalf of the subject (sub)" by nesting (the outermost is the current actor; going inward are earlier actors).

- **No token exchange.** Nexus does not exchange MCP tokens for other tokens to send to other servers (principle 3). "Acting on behalf of" inside Nexus is already proven by the **delegation certificate chain** (`nexus/certificate.go`, `Chain []CertLink`: delegator → delegated session, scope only narrows downward).
- Instead, **only the record format is aligned with the RFC 8693 shape.** Ledger records of remote connections (`tool.call`, `tool.approval`, and the actor metadata of `message.sent`) carry:

```json
"act_chain": {
  "sub": "person:<account>",
  "act": {"sub": "mcp_client:<client_id>", "client_name": "Claude", "consent": "<consent id>",
          "act": {"sub": "session:<slv_…>", "delegation": "<del_…>"}}
}
```

  How to read it: the person (sub) allowed the MCP client to connect (consent), and that client performed this action as the connection session (delegation). Work handed to a subsession with `delegate_task` gets one more certificate chain link in the receiving session's records.
- Review results (summary):
  - Order: in RFC 8693 the outermost is the **current** actor. The JSON above is in "provenance order" starting from the person, so the field is named `act_chain` (our format) and documented so it is not confused with the `act` claim. If it ever needs to be exported, it will be reversed into a standard `act` then.
  - `may_act`: the consent record corresponds to `may_act` (this person allows actions by this client_id). It is referenced by consent ID, with no separate claim.
  - The actor chain is a **description**, not authority: decisions are always made by the connection session's delegation. If any link of the chain breaks (consent revoked, token revoked, delegation expired), later calls are refused.
  - `clientInfo` and `client_name` sent by the client are self-reported, so they are for display. Identity is client_id (registration) + consent (person).

## 7. Implementation units and tests (actual files)

| Unit | Location | Tests |
|---|---|---|
| Streamable HTTP adapter (same `nmcp.Server`) | `internal/nmcp/httpserver.go` | `httpserver_test.go`: initialize→`Mcp-Session-Id` (JSON), tools/call SSE, notification 202, another token's session 404, Origin 403, 401+`resource_metadata`, read only after SSE is written, dropped POST has no response or receipt, elicitation over the POST stream and its answer by POST 202, GET stream notifications and `Last-Event-ID` resumption, DELETE |
| Conformance (engine = stdio = HTTP) | `internal/nmcp/conformance_test.go` | The existing three scenarios over three paths |
| OAuth server, resource checks, person paths | `internal/mcpauth/server.go` | `endpoint_test.go`: discovery documents, 401 header, resource required, PKCE, code reuse → consent revoked, other audience, refresh and licence tokens 401, `/v1` refuses `ntm_`, refresh rotation and reuse → consent revoked, person revocation → open connections end too |
| Storage | `internal/mcpauth/store.go` (memory), `postgres.go` (`mcp_oauth_*`, `gate_meta` key `mcp_oauth`=1) | The tests above with the memory store |
| Connection session, delegation, actor chain | `internal/mcpauth/connect.go` | CLI code consent → `remote` session `mcp:Claude`, out-of-delegation `delegate_task` is `refused`, `act_chain` on `tool.call`, the same consent gives the same session |
| Mail consent and mail approval fallback | `server.go` (`mcp_connect`), `connect.go` `MailApprovals` (`mcp_approval`), `internal/nexusops/contract.go` `mailApproval` | Mail consent; `request_approval`: one mail on the first call, the same request when called again, after approval `once` and a single Consume |
| `remote` runner | `nexus/model.go`, `nexus/issuance.go`, `nexus/httpapi/roots.go`·`delegations.go` (refused by the public API) | `internal/nexusserver/inprocess_test.go` |
| In-process calls and token separation | `internal/nexusserver/inprocess.go` (`InProcess`, `PersonAuth`, `/v1` refusing `ntm_`/`ntr_`) | Tests in the same file: `/v1` and streams with an in-process principal; over the network, placeholder tokens, `ntm_` and `ntr_` get 401; the public API refuses `remote` roots |
| Server wiring | `cmd/nexus/remote_mcp.go`, `cmd/nexus/main.go` (routes, cleanup), `migrate_fd.go` (migration step "mcp oauth"), `internal/nexusserver/config.go` (`NEXUS_MCP_ISSUER`) | Build and existing tests |
| Approval server kinds | `gate/change_approval.go` (allows `mcp_connect`, `mcp_approval`) | Existing tests |
| Person CLI (client, outside this repository) | `newtype nmcp authorize CODE`, `clients`, `revoke ID|name` | Client repository |

Deployment: **an upgrade without input does not run migrations.** ① Deploy the new image (without `NEXUS_MCP_ISSUER`) → ② run an explicit migration with `nexus migrate`, and if the runtime role differs from the migration owner, grant runtime privileges on the new tables (migrations revoke only PUBLIC): `mcp_oauth_clients` SELECT/INSERT/UPDATE/DELETE; `consents`, `codes`, `tokens` SELECT/INSERT/UPDATE; `settings` SELECT/UPDATE → ③ set `NEXUS_MCP_ISSUER=https://nexus.example.com` in the environment. Without this value the endpoint is off. With the value but without the tables, the server does not start ("run explicit migration"). The mail paths (consent mail, approval mail) work only when **the approval server (`nexus approvals`) is the same version** (the approval server validates the new kinds `mcp_connect` and `mcp_approval`). Until then the mail button cannot send mail (the page proceeds only by CLI code), and the mail step of `request_approval` is `approval_unavailable`.

## 8. Decisions (2026-10-04)

1. Consent confirmation: **both** the one-time mail link and the CLI code. Passkeys will later replace both.
2. A new runner **`remote`** (a Go enum; sessions are stored as JSON documents, so no storage migration is needed). `local` plus a title prefix is not used.
3. Registration is **dynamic registration only**. CIMD after an SSRF review.
4. Waits: mail 15 minutes, elicitation 2 minutes.

## 8a. Independent review fixes (2026-10-04, 12 FIX-FIRST items)

1. The approval server `ClientID` of both mail flows is unique per request (consent = the `mcr_` pending ID, approval = a new random `mcpa_`). The approval journal is permanently idempotent on `Requester+ClientID`, so a fixed value would have worked only once. Tested twice each with the real `gate.FileChangeStore`.
2. Refresh rotation is atomic (`UPDATE … WHERE verifier=$1 AND kind='refresh' AND NOT revoked`; 0 rows = reuse → consent revoked). Concurrency test.
3. Device code phishing: a `GET /v1/mcp/authorize?user_code=` preview (client, redirect target, request time, requesting IP — `CF-Connecting-IP` behind a tunnel) → the CLI shows it and asks y/N → then the POST. The mail subject and impact include the code and the redirect target.
4. Flood limits: pending requests 5 per client and 10 per IP (256 overall); consent mail 3 per day overall and 1 per day per client (24-hour window); approval mail 3 open per connection session, 15-minute expiry, 20 per hour overall; registrations 10 per hour per IP (+60 per minute overall); registrations without consent are deleted after 24 hours. The approval server's permanent request limit (shared with default-model approvals) is also respected.
5. A consent never outlives the person's credentials: on `/mcp` checks, token issuance and refresh, the account must have a live licence and login and pass the owner policy (1-minute cache). Absolute consent lifetime 90 days; token expiry never goes past it.
6. Instead of issuing a new root on every initialize, a live remote root (with at least 1 hour left) is reused. Session seat reservation happens under a lock.
7. When another session's `delegate_task`, a person's root (`to_session_id`) or an observer root targets a remote session, the service refuses (only the connector's remote root is allowed).
8. Remote elicitation answers are recorded as `mcp_client:<id>:elicitation` (not as a person).
9. The approval server mails only the owner, so if the consent's email is not the owner's, mail approval is not attempted and the result is `approval_unavailable` (owner only).
10. Open GET/POST streams recheck the token on every heartbeat and end after revocation or expiry.
11. The verification step of the fd migration also checks the `mcp_oauth` version.
12. The consent page's polling asks the approval server at most once every 3 seconds per request, and the account check happens before Consume, so a failure can be retried.

Tests: `internal/mcpauth/review_fixes_test.go` (the client's preview and y/N tests are in the client repository).

## 8b. Re-review fixes (2026-10-04)

- **Mail consent switch (off by default)**: the approval store's request limit is a lifetime cumulative count and is never cleared (shared with default-model approvals). So mail consent is off by default, and a person turns it on and off **by command and by conversation**.
  - Server: `GET/PUT /v1/mcp/settings {"mail_consent": bool}`. Person authentication only (session tokens and `ntm_` refused), and only the owner may change it (`owner_only` 403). The value is stored in a single `mcp_oauth_settings` row (the same `mcp_oauth` schema 1; not yet deployed, so the version was not bumped) together with who changed it and when. Changes are recorded in the ledger as `mcp.settings.changed` (from/to/by) for that account's remote connection sessions and the operator seat. The consent page shows the mail button only when it is on; when it is off, `authorizeMail` refuses.
  - CLI: `newtype nmcp mail-consent [on|off]` (status without an argument). When turning it on, it shows what this allows (an unauthenticated requester can trigger owner mail, within the daily budget) and asks y/N.
  - TUI: the conversational tool `nmcp_settings` (get/set) and `/nmcp mail-consent [on|off]`. The tool works only in turns typed by a person (inbox and background turns are refused), and requires human approval before changing anything (class remote — no mode auto-approves it).
- **Daily approval mail budget**: 3 per connection (consent) per day, 10 per day overall (replacing the hourly limit).
- **IP limits are per IPv6 /64**, the overall cap on pending requests is 64, and pending requests not polled for 2 minutes are dropped.
- **Confirmation only for previewed requests**: `POST /v1/mcp/authorize` requires the `request_id` received from the preview, and it must match the code.
- **Execution grants**: issuing an execution grant is refused when the sending session is remote (a remote connection cannot direct local tool execution).
- Remaining (follow-up): a separate approval store or separate limit for the `mcp_*` kinds only. Two overlapping first initializes can create two roots (low).

## 9. Implementation status and remaining work

- All of the server side in §7 is implemented and the tests pass (`go test ./internal/mcpauth ./internal/nmcp ./internal/nexusserver ./nexus/...`).
- Checks after deployment: the three SSE checks of §5, and the real OAuth flow with a claude.ai connector or `claude mcp add --transport http nexus https://nexus.example.com/mcp` (consent page → `newtype nmcp authorize CODE`).
- Remaining: passkey consent, CIMD; the connection session's Tasks and resumption buffer live in process memory (after a restart the client re-initializes), and so do pending consent requests (after a restart the client starts over).
