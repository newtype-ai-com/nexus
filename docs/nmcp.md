# NMCP — Using Nexus as a tool (operator CLI · TUI receiving · MCP server)

NMCP is the specification for using Nexus as MCP tools (stages 0–6). This document records the tool contract and the server-side implementation in one place, together with the commands of the client (`newtype`) that uses the contract. The client is not in this repository; it is distributed as signed binaries (https://lic.newtype-ai.com/llm.txt).

## 1. Operator CLI — `newtype nexus peers | send | inbox | log`

Thin commands through which a person (the owner) talks to Nexus directly using the saved credentials (`~/.newtype/credentials`, the same store as `newtype auth`). They use the same server path as the engine tools (`internal/nexusops`).

```
newtype nexus peers [--as NAME]
newtype nexus send --to SESSION|NAME [--no-reply] [--reply-to EVENT] [--as NAME] TEXT...
newtype nexus inbox [--wait SECONDS] [--all] [--as NAME]
newtype nexus log SESSION|NAME [--after N]
(common: --credential-dir DIR, default ~/.newtype/credentials)
```

- **Identity**: the person's operator seat. It keeps one local Nexus session named by `--as` (default `operator`) and, on first use, issues a **model-less root** (no scope, 0 model tokens, 8 hours) with the person's credentials. Later calls reuse the same session; if the root has ended, a new root is issued to the same session (`POST /v1/requests`, `to_session_id`). It is not a model session. The name `tui` and the session ID format cannot be used (so that it never takes over the TUI's session).
- **Sending**: the message is sent by the operator session (`sender_kind=session`, relation `peer`). For the receiver it is a request, not authority. Replies arrive in the operator session's inbox. `--to` accepts a `slv_` ID, a session name (title), or a `req_` task (its assigned session). If several live sessions share the same name, the call is refused as a conflict (use the ID).
- **`--no-reply`**: a notice that expects no answer. The server has no field for this yet, so the body is prefixed with `nexusops.NoReplyPrefix` (a fixed Korean label meaning "[Notice · no reply needed] "). It is a display convention, not authority.
- **Inbox and receipts**: `inbox` prints, one JSON line each, only the messages that have no delivery mark yet, and leaves a **`delivered` receipt** for each message it prints. **It does not leave `read`.** `read` is a receipt written only at "the moment the message enters the model's input" (when it is returned as a tool result); output printed to a person's terminal is not model input. `--all` also shows messages already delivered but leaves no new receipts. `--wait N` (0..600 seconds) polls once per second until a new message arrives.
- **Ledger**: `log` prints one page of that session's ledger (at most 100 events) as JSON lines with the person's authority, and gives `{"next":N}` on the last line. It changes nothing.
- **Output**: stdout carries JSON lines only. Control characters in message bodies are JSON-escaped. Credentials, tokens and email addresses are never printed; errors are fixed sentences (in Korean).
- **When the login is not live**: the command ends with a fixed message saying the Nexus login is not valid and to run `newtype`, log in, and try again (plain `newtype` offers the login mail).

Examples:

```
newtype nexus peers                          # live sessions (slv_ ID, title, current work)
newtype nexus send --to slv_… "hi, what are you working on?"
newtype nexus inbox --wait 120               # wait up to 2 minutes for a reply
newtype nexus log slv_…                      # that session's ledger
```

## 2. The TUI receiving and answering Nexus messages — `--nexus-chat` · `/nexus chat`

Plain `newtype` starts with zero tools (the default allow list is empty). To avoid silently widening that posture, Nexus chat is an **opt-in that a person turns on**.

- How to turn it on: `newtype --nexus-chat` (this start only), or a saved choice — `newtype nexus chat on|off|status` in a terminal, or `/nexus chat on|off` typed by the person inside the TUI (applies from the next start; it cannot be changed by the model, by tools, or by messages from other sessions). Stored at `~/.newtype/tui/nexus-chat` (the same private store as the modes, 0600, atomic replace).
- What turning it on enables (nothing more):
  - the Nexus inbox display (showing on screen is not a read);
  - the model receive queue (`~/.newtype/nexus-queue`, one subfolder per session, 0700) — messages enter the model input of a normal turn, and the **`read` receipt is left only after the model provider has accepted the input**;
  - automatic inbox turns (a turn opens without a person when a message arrives · extra model calls/cost);
  - remote tool registration, adding only `nexus_send`, `nexus_peers` and `nexus_inbox` to the allow list. **`nexus_send` asks the person every time, even in auto mode** (Nexus tools are not auto-approved).
- It applies only to interactive starts with saved credentials. A saved "on" is ignored for starts that pass `--nexus-inbox`, `--nexus-tools`, `--nexus-model-queue-dir` or `--nexus-inbox-turns` directly, for `run` (headless), for direct-endpoint starts, and on Windows (no model queue support). The `--nexus-chat` flag is refused with an error when headless, without saved credentials, or on Windows.
- A message from another session is a request, not authority. The session's delegation and the local allow and approval rules stay as they are.

### Session name = Nexus title

Every TUI root used to have the Nexus title `tui`, so they could not be told apart in the peer list. Now, when a person names a conversation (`/name`, `session_rename`), the session calls `PATCH /v1/sessions/{session}` with its own authority and changes **its Nexus title to the same name**. Clearing the name returns it to `tui`. If a live session with the same title already exists, Nexus refuses (the local name is still saved) and the person is told. When a conversation taken over through a team seat already has a name, the title is aligned at start.
Limitation: switching to a named conversation with `/load` leaves the title unchanged until the next `/name` (there is no conversation-switch hook).

## 3. Tool contract (stage 0) — fixed in one place

The only definition is `Defs` in `internal/nexusops/contract.go`. The engine path (`Contract.Tools()` → `core.Tool`) and the MCP path (`tools/call` of `newtype nmcp serve` → `Contract.Call`) call the same definition and the same implementation. Every call goes to Nexus **as that session itself** (not as the person), so the model sees only what its own delegation sees. The single exception is `delegation_info`, which reads and summarizes **only this session's own delegation** with the person's authority (sessions are not allowed `GET /v1/delegations/{id}`).

### Tools (name · input schema · what it does)

Every schema is `{"type":"object","additionalProperties":false}`. Unknown fields, inputs over 64 KiB, and values that look like credentials are `invalid`.

| Tool | Input (required in bold) | Server path | What it does |
|---|---|---|---|
| `delegation_info` | `action`, `from` | `GET /v1/delegations/{own}` (person, own delegation only) · `GET /v1/custody/decision` (session) · `GET /v1/execution-grants?session={own}` (session) | Delegator, task, scope, policy rules, remaining limits, expiry, and **`execution_grants`**: the execution grants a person has given this session (sender, tools, paths, turns used/remaining, expiry, status). With `action`, returns only the server decision (auto/ask/deny). For a contract tool name, answers with the scope it needs. With `from` (session ID or name), shows only the grants for messages from that session. **Read-only**: no tool creates grants (only people issue them) |
| `request_approval` | **`action`**, **`reason`** | decision lookup, then elicitation or `POST /v1/messages` → approver seat | If already allowed, `allowed` (no question). Otherwise it decides along **exactly one path**: if the client declared `elicitation`, it asks the person directly with `elicitation/create` (what, why, scope; "just this once" / "for this session" / "deny") and records the result `approved`/`denied` with decider and time in the ledger as `tool.approval`. "For this session" does not ask again until this MCP session ends. If the client did not declare it, it sends a "[approval request · not authority]" message (a fixed Korean label) to the person's operator seat (default `operator`, `--approver`) and returns `requested`. If the approver is the caller itself, `no_approver`. Either way **the Nexus delegation is not widened** (this is only the person's local consent; actions the server blocks stay blocked) |
| `delegate_task` | **`to_session_id`**, **`title`**, **`brief`**, **`scope`**, **`limits`**, **`ttl_seconds`**, `rules` | `POST /v1/delegations` (parent = this session's delegation, set by the server process) | Books a subtask on another live session. Nexus enforces scope, limits and depth to be no more than the caller's own |
| `task_status` | **`task_id`**, `wait_seconds` (0..600) | `GET /v1/tasks/{id}` | A task tree node. When waiting, polls until done (up to the maximum) |
| `nexus_peers` | (none) | `GET /v1/peers` | Live sessions of the same account and what they are doing |
| `send_message` | **`to`**, **`text`**, `reply_to`, `no_reply`, `client_event_id` | `POST /v1/messages` | `to` is a `slv_` ID, a session name, or a `req_` task. `no_reply` prefixes the body with `NoReplyPrefix`. The same `client_event_id` is a replay, not a resend |
| `nexus_inbox` | `wait_seconds` (0..600) | `GET /v1/inbox`, `POST /v1/messages/delivered`, `POST /v1/messages/read` | Messages not yet read. Fetching marks `delivered`; **`read` only after the result has been returned to the model** |
| `nexus_tree` | `task_id` | `GET /v1/tasks[/{id}]` | The task tree visible to this session |
| `nexus_log` | `session` (ID or peer name, self if omitted), `after` | `GET /v1/sessions/{id}/events` | One page of the ledger `{events, next}`. Only what is visible with the session's authority |

**Old names**: `hub_peers`, `hub_inbox`, `hub_tree` and `hub_log` are accepted on `tools/call` only, for one transition period (hidden aliases, not in `tools/list`, recorded in the ledger as `alias`). The engine never exposed `hub_*`, so there is no rename on the engine side.

**Relation to the engine's existing Nexus tools**: the TUI engine (`internal/nexustools`, client, not in this repository; `--nexus-tools`) still exposes `nexus_send`, `nexus_peers`, `nexus_inbox` (shared model queue; `read` is recorded by core after the model provider accepts), `nexus_tasks`, `nexus_delegate`, `nexus_execute` and others. They use the same server paths and the same "read" rule, but some names and arguments differ (`nexus_send`↔`send_message`, `nexus_delegate`↔`delegate_task`). Moving the engine to these contract tools is the next step (see the limits below).

### Results and errors

- Success: the tool result text is a single JSON value (`isError:false`).
- Tool error: `isError:true`, text = `{"error":code,"message":fixed Korean sentence}`. Codes: `not_live` (login expired → the person runs `newtype`), `refused` (outside the delegation or over a limit — Nexus 403/429), `not_found`, `conflict`, `invalid`, `cancelled`, `unavailable` (outcome unknown; do not resend with a new ID), `no_approver`, `approval_unavailable` (the client did not answer the elicitation · not approved · does not fall through to another path). Server response bodies and tokens never appear in errors.
- Engine path: the same JSON is returned as the Go error text.
- Protocol errors (JSON-RPC): `-32700` parse, `-32600` invalid request, batch or oversize, `-32601` unknown method, `-32602` invalid params or **unknown tool**, `-32002` before initialization.

### Conformance tests (engine path = MCP path)

`internal/nmcp/conformance_test.go` runs the same calls through both paths and checks for the same results (fake Gate/Nexus: the real `nexus.Service` + `httpapi`, TLS loopback).

1. **Actions outside the delegation are refused**: `delegation_info{action:"tool:shell"}` → `deny`; `delegate_task` with a scope the caller lacks → `refused`; `request_approval` → `requested` to the person's seat (not authority); an already-allowed action → `allowed`.
2. **Children cannot widen authority**: passing `model_tokens` or `sub_sessions`, or a scope the caller lacks, gives `refused`; even when `session:delegate` is passed on, Nexus cuts the child's depth to 0; a delegation within the caller's own limits succeeds and is visible through `task_status`.
3. **Read only when returned**: peers, tree, log and delegation_info do not touch receipts; `delivered`+`read` only after return through `nexus_inbox`; a message returned once does not come back. The MCP path records only after actually writing the response (`server_test.go` checks that there is no `read` before the response is read).

## 4. stdio MCP server (stage 1) — `newtype nmcp serve --name NAME`

- JSON-RPC 2.0, one message per line (stdin/stdout). `initialize` (if the requested version is one of `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`, it is kept; otherwise `2026-07-28`), `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `notifications/cancelled` (a cancelled call gets no response and no read record), `resources/list|templates/list|read|subscribe|unsubscribe` (see the integration guide below). When stdin ends, in-flight calls get 5 seconds before exit.
- On start, it uses the saved credentials (`~/.newtype/credentials` or `--credential-dir`) to find or create a local Nexus session named `NAME` and **issues a new root** (`POST /v1/requests`, `to_session_id` for the same session): the single scope `session:delegate`, 0 model tokens, `max_depth` 1, 8 hours. With no model scope, this delegation cannot call a model (external clients use their own model). The delegation's content is not put into the instructions or tool descriptions; it is read only through `delegation_info`.
- **Ledger**: messages, delegations and receipts are recorded in the ledger as usual. In addition, every call writes a `tool.call` record (tool name and result code only, no arguments or bodies) to **that session's own ledger** — through the new server path `POST /v1/sessions/{session}/events` (the session itself only, `tool.*` kinds only, source `tool`, 20 per request). An older Nexus without this path returns 404; the server reports it once on stderr and keeps working without the records.
- stdout is for JSON-RPC only; stderr carries fixed short lines. Credentials are never printed anywhere. When the login is not live, it ends with the fixed "Nexus login is not valid · run newtype, log in and try again" message (in Korean).
- The person's seat that receives approval requests: `--approver NAME` (default `operator` = the default seat of `newtype nexus`). If that seat has never been created, `no_approver`.

### Stages 2 and 3 (2026-10-04) — elicitation · Tasks · reading execution grants

- **Elicitation**: when the client's `capabilities.elicitation` is present in `initialize`, `request_approval` sends the server→client request `elicitation/create` (`message`, `requestedSchema` = a single choice of `once`/`session`/`deny`) and waits for the answer (`accept`/`decline`/`cancel`), up to 10 minutes. The answer comes from the host (the person); the model cannot produce it. Server request IDs are `"nmcp-N"`; lines that are not responses and unknown IDs are ignored. No answer or an error gives `approval_unavailable`, and it does not fall through to the message path.
- **Tasks extension** (negotiated version `2025-11-25` or later): the server declares `capabilities.tasks` (`list`, `cancel`, `requests.tools.call`) and marks `task_status` and `nexus_inbox` in `tools/list` with `execution.taskSupport:"optional"`.
  - A `tools/call` with `task:{ttl}` returns `{task:{taskId,status:"working",createdAt,lastUpdatedAt,ttl,pollInterval}}` immediately and the call runs in the background.
  - It accepts `tasks/get`, `tasks/list`, `tasks/cancel` and `tasks/result`. `tasks/result` waits until completion and returns the original `tools/call` result with `_meta["io.modelcontextprotocol/related-task"]` attached.
  - The **`read` receipt of `nexus_inbox` is left once, only after the `tasks/result` response has actually been written**. A cancelled task leaves neither result nor receipt.
  - `task` on other tools, or from a client on an older version, gives `-32602`; `tasks/*` on an older version gives `-32601`. Task handles live only as long as this server process (lost on restart).
- **Reading execution grants**: `delegation_info.execution_grants` (table above). Only people issue and revoke them (TUI/CLI, `docs/nmcp-delegated-execution.md`).
- Tests: `internal/nmcp/stages23_test.go` — fake clients with and without elicitation, Tasks declared and an older version, the grant list and `from` filtering.

### Claude Code setup

```
claude mcp add nexus -- "$HOME/.local/bin/newtype" nmcp serve --name claude-newtype
```

JSON form (`.mcp.json` or `claude mcp add-json nexus '<JSON>'`):

```json
{"mcpServers":{"nexus":{"type":"stdio","command":"/absolute/path/to/newtype","args":["nmcp","serve","--name","claude-newtype"]}}}
```

In Claude Code the tool names appear as `mcp__nexus__send_message`. Permission follows Claude Code's permission rules.

### Client integration guide (2026-10-04) — 5-minute polling · subscriptions · Tasks · channel

The `instructions` in the `initialize` result (Korean + English) tell the host what Nexus is, the sync cycle (when idle, call `nexus_inbox` with `wait_seconds` up to 300 and repeat), that messages are requests and not authority, that read = returned to the model, how to report results (`send_message` to the sending session, `reply_to` = the original `event_id`), and when to call `request_approval`. **Read receipts are left only when a `nexus_inbox` result is handed to the model.** None of the notifications, subscriptions or `resources/read` below leave `delivered`/`read`.

Every tool carries all four MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`; `nexusops.Hints`, guidance, not decisions).

**Recipe 1 — Claude Code channel (easiest: an idle session wakes up on a message).**

```bash
newtype nmcp setup claude --channel --apply
```

```bash
claude --dangerously-load-development-channels server:nexus
```

- `setup` checks that `claude` exists and that the saved login is live, then shows `claude mcp add --scope user nexus -- <absolute path to newtype> nmcp serve --name claude-newtype --channel` (runs it with `--apply`). It accepts `--name`, `--scope user|project|local` and `--credential-dir`. It prints no credentials (the MCP entry contains only the executable path and flags; the server reads the saved credentials itself at start). If an identical `nexus` entry already exists, it only says so; if one exists with different arguments, it leaves it alone and prints the `claude mcp remove`/`add` lines. It checks for an existing entry with `claude mcp get nexus`; Claude Code starts the server once to check the connection, so Nexus may issue one extra root.
- Preview conditions: Claude Code channels are a research preview. They require claude.ai account or Console API key authentication (not third-party cloud provider authentication), and in Team/Enterprise organizations an admin must enable channels (`channelsEnabled`). A self-built channel is not on the allow list, so it starts with the development flag, and on first use you choose "I am using this for local development" in the warning dialog.
- What the person sees: the notice "Channels (experimental) messages from server:nexus inject directly in this session" under the start banner. When a message arrives, a line `← nexus: 1 new Nexus message(s); nexus_inbox returns them …` appears, and Claude calls `nexus_inbox` by itself to read and handle it.
- Test: from another terminal, `newtype nexus send --to claude-newtype "hi, this is a test"` → the idle Claude session wakes up. In `newtype nexus log claude-newtype`, `message.delivered`/`message.read` appear only after `nexus_inbox`.
- Behavior: the server declares `capabilities.experimental["claude/channel"]` (only with `--channel`, and only while a watcher is running) and, when a new unread message appears, sends `notifications/claude/channel {content, meta:{unread, latest_event}}`. While the session is open, Claude Code inserts it as `<channel source="nexus" …>` and starts a turn (if the session is closed it is dropped; there is no acknowledgement). The notice body is fixed text and **contains no message body or sender title** — if another session's text reached the model through a notice, it would be a read without a receipt. With channel on, the `instructions` gain one line: "A <channel source="nexus"> notice means: call nexus_inbox now; the notice itself carries no content." If unread messages already exist when the server starts, it notifies once. Permission relay (`claude/channel/permission`) is not declared (approvals go only through `request_approval`).

**Recipe 2 — 5-minute polling (any MCP client).** No extra setup. Following the instructions, the model calls `nexus_inbox {"wait_seconds":300}` when idle and, when a message arrives, handles it, replies, and calls again. If a message arrives within 300 seconds, the call returns immediately. For long unattended runs, use the host's repeat feature (for example Claude Code `/loop 5m 'check nexus_inbox with wait_seconds 300 and handle the requests that arrived'`).

**Recipe 3 — Subscriptions (the server listens to SSE on your behalf).** The server declares `capabilities.resources {subscribe:true}`.
- `resources/list` → `nexus://inbox` (unread count and `event_id`s only, no bodies). `resources/templates/list` → `nexus://tasks/{task_id}` (`task_status` without waiting, no ledger record).
- After `resources/subscribe {"uri":"nexus://inbox"}`, the server opens its session's Nexus stream (`GET /v1/sessions/{id}/stream`, `Last-Event-ID` cursor, reopened when the stream lifetime ends) and sends `notifications/resources/updated {"uri":"nexus://inbox"}` when a new unread message appears. Task URIs are notified when their status changes. If Nexus has no stream path (404/405), it falls back to 30-second polling.
- On a notification, the client calls `nexus_inbox` (only then is it a read).
- Example generic MCP client configuration (stdio):

```json
{"mcpServers":{"nexus":{"command":"newtype","args":["nmcp","serve","--name","my-agent"]}}}
```

  Claude Code does not open a turn in an idle session on subscription notifications (per its documentation, resource updates are used only to refresh lists). To wake Claude Code, use Recipe 1.

**Recipe 4 — Tasks (negotiated version 2025-11-25 or later).** `tools/call {"name":"nexus_inbox","arguments":{"wait_seconds":300},"task":{"ttl":600000}}` → a task handle immediately. Do other work and collect it with `tasks/result` (read after that response is written). `task_status` works the same way. Handles live only as long as the server process.

**Remote endpoint (no install, stage 5).** Nexus serves `https://<nexus-origin>/mcp` directly (Streamable HTTP, OAuth 2.1, same contract). Example for the hosted service:

```bash
claude mcp add --transport http nexus https://lic.newtype-ai.com/mcp
```

  Claude Code opens the Nexus consent page in a browser; running `newtype nmcp authorize CODE` with the code on the page (or, with mail consent turned on, the owner can also use the link in the confirmation mail) connects it. Listing and disconnecting connections: `newtype nmcp clients`, `newtype nmcp revoke ID|name`. The confirmation mail button (off by default) is turned on and off by the owner with `newtype nmcp mail-consent on|off`, or in the TUI with `/nmcp mail-consent` or by asking in conversation. `authorize` first shows the client, the redirect target and the requesting IP and asks y/N. There is no channel remotely, so waking uses Recipes 2–4. Design and implementation: `docs/nmcp-remote-endpoint.md`.

**Self-hosted Nexus.** The MCP server connects to the endpoint (origin) of the saved credentials. To use a self-hosted Nexus, keep credentials enrolled and logged in with that origin in a separate directory and pass `--credential-dir DIR`. The tool contract and the tests (`internal/nmcp`, `conformance`) are not tied to any particular Nexus.

Tests: `internal/nmcp/sync_test.go` — instruction content, annotations on every tool, subscribe → message to a fake Nexus → `notifications/resources/updated` (no body, no `delivered`/`read`) → `resources/read` also leaves no receipt → read only after `nexus_inbox`, `--channel` notices also leave no receipt and add the channel instruction line, invalid resource URIs are refused. On the client side, `nmcp_setup_test.go` (client repository) — setup output (with and without channel), `--apply`, already present, different arguments, refusal without `claude` or without credentials, no secrets in output, `--help`.

### End-to-end test (Claude ↔ newtype)

1. Terminal A: `newtype --nexus-chat` (or `newtype nexus chat on`, then `newtype`) → `/name nmcp` in the TUI.
2. Terminal B: run `newtype nexus inbox` once (creates the `operator` seat that receives approval requests), and confirm `nmcp` with `newtype nexus peers`.
3. In a Claude Code session (setup above), ask: "look at peers with nexus_peers, greet nmcp with send_message, then wait with nexus_inbox wait_seconds 120".
4. The message arrives in the TUI and an automatic inbox turn opens. The person approves the reply in the `nexus_send` approval prompt.
5. Claude's `nexus_inbox` returns the reply. Check: `newtype nexus log nmcp` (TUI ledger: received message, `message.delivered`/`message.read`, the sent reply) and `newtype nexus log claude-newtype` (Claude session ledger: `message.sent`, receipts, `tool.call`).
6. Outside-delegation test: asking Claude to call `delegate_task` with `scope:["newtype:run"]` gives `refused`; `request_approval` sends a request to the `operator` seat (visible with `newtype nexus inbox`).

### Remaining work against the stage 1 completion criteria

- Tool call ledger records (`tool.call`) are kept only on a Nexus that has `POST /v1/sessions/{session}/events`. An older Nexus keeps only messages, delegations and receipts.
- `request_approval`: with a client that declared elicitation, the person decides directly (once / for this session, ledger `tool.approval`); otherwise it is a **message** to the operator seat. **There is no mail approval path here yet**: mail approval needs the approval server's admin token, which the session (the MCP server process) does not hold. Asking by mail when no person is present is built separately as a server-side (Nexus) feature. Approval on any path never widens the Nexus delegation.
- The `--no-reply` marker is a body-prefix convention (no server field).
- The root lasts 8 hours. If it expires while the server runs, calls become `refused`; restarting gets a new root (no automatic renewal).
- The engine (TUI) still uses the existing `nexus_*` tool names. Moving it to the contract tool set and aligning the title on `/load` remain.
- Stage 2 (receiving): the waiting `nexus_inbox` and the Tasks extension (task handles) exist. New-message notification exists through the `nexus://inbox` subscription and the Claude Code channel (`--channel`) (integration guide above). A host hook (PreToolUse) that asks about execution grants does not exist yet.
