# Delegated execution of Nexus-originated turns (NMCP stage 3)

2026-10-04.

## Background

Before grants were introduced, a Nexus message sent by another session was delivered and read, but the TUI's automatic inbox turn did not execute tools. That was correct behavior: **a message is a request, not authority.** Only turns typed by a person executed tools, so a person had to type "go ahead" into the TUI directly. This is why grants were introduced. Since grants, delegated work runs to completion within its scope without human intervention.

What was needed is an **execution grant that a person scopes and issues**. For example: "task messages from the operator may run file edits and tests inside repository X for 8 hours, up to N turns". The receiving session executes Nexus-originated work within that scope without human input.
- Anything outside the scope is denied or turned into an approval request. If a person is present, they are asked on the spot; if not, it is denied (mail approval is stage 2).
- Every decision is recorded in the ledger.

## 1. Grant format

| Field | Meaning |
|---|---|
| `id` | `xgr_<ULID>` |
| `grantor` | The person who issued it (PrincipalUser). Sessions cannot issue grants |
| `receiver` | The session that executes |
| `delegation_id` | A live delegation held by the receiver. The grant never outlives it; revoking this delegation also ends the grant |
| `senders` | Only messages sent by these sessions can serve as the basis for the grant (at most 16) |
| `tools` | Actions such as `tool:edit_file`, `tool:run_*`. A trailing `*` is a prefix match (at most 32) |
| `paths` | Absolute, canonical paths on the receiver's computer (at most 16). `P/**` means P and everything under it; anything else means exactly that path. `/**` is refused |
| `max_turns` | 1–1000. **Each distinct source message is one turn.** Calling several tools for the same message does not add turns |
| `issued_at`, `expires_at` | TTL at most 7 days, and never past the delegation's expiry |
| `note` | A description written by the person. It is redacted |

Queries additionally return `status` (active, revoked, expired, exhausted), `turns_used` and `issued_seq`.

## 2. Who issues grants

**Only people** issue grants (the server enforces `actor.Kind == PrincipalUser`). They do so through a TUI command or the CLI (client work, §7).
- Example: `/grant @operator tools=edit_file,run_tests path=. turns=20 for=8h`
- Example: `newtype nexus grant …`
- Grants can also be issued in conversation (settings must be reachable by conversation too). The TUI's `execution_grant` tool (action propose|list|revoke) turns a request such as "let operator give the instructions and this session execute them" into the same arguments as `/grant` and shows the person a preview in Korean (instructing party → executing party, tools, paths, turns, expiry, and what always stays under human confirmation). Only after the person approves does it issue the grant through the same person-authenticated path as `/grant`. The approval class is `grant`, so neither auto nor self-conscious mode auto-approves it. Revocation also requires human confirmation. It is available only in turns typed by a person; Nexus (inbox) and background turns are refused.
- `--tools all` means all of the TUI's local tools (file, shell, memory; `execgrant.LocalTools`). Re-delegation and secrets are never part of a grant, by design. `--ttl max` ("until revoked") is the server maximum of 7 days, and without `--turns` the turn count is also the maximum of 1000.

**Limitation:** the local TUI holds the person's licence/login, so dropping the session header authenticates it as the person. "Only people" is a server policy, not a cryptographic distinction. Where a stronger guarantee is needed, stage 2 adds a fresh human check such as a passkey at issuance.

**Revocation:** a person can revoke at any time. The receiver session can also give up a grant itself.

## 3. Storage and enforcement (server)

**No new table.** As with durable execution, the **receiver session's ledger** is the source of truth. There is no schema migration and no change to production database permissions, and memstore and pgstore run the same code.

| Ledger key (`client_event_id`) | Kind | Content |
|---|---|---|
| `xgrant:<id>:issued` | `execution_grant.issued` | The whole grant (source `"hub"`, the server-written source value; Actor is the person) |
| `xgrant:<id>:revoked` | `execution_grant.revoked` | Reason |
| `xgrant:<id>:turn:<n>` | `execution_grant.turn` | The n-th turn, source message |
| `xgrant:<id>:src:<event>` | `execution_grant.turn_source` | Source message → turn number |
| (no key) | `execution_grant.decided` | One per decision: action, paths, input_hash, effect, reason, turn |

**Decision order** (`DecideExecutionGrant`, called only by the receiver session; one transaction, a `decided` record per decision):
1. The grant exists, is not revoked, and has not expired. Otherwise **deny**.
2. Check the source message. Otherwise **deny**.
   - It must be exactly that `seq`/`event` in the receiver's ledger.
   - It must be `ForInbox`, of kind `message`, and its sender must be a **session** listed in `senders`.
   - It must come **after** the issued record in the ledger. This is judged by ledger order, not by clocks.
3. The action is within `tools` and every path is within `paths`. Otherwise **ask** (out of scope).
4. The delegation chain's policy `decide(…)` is still `auto`.
   - `ask` gives **ask**; `deny`, or a delegation that has ended, gives **deny**. A grant can never be wider than the policy.
5. Count turns. A new source message uses one turn; going over the limit gives **deny**.
6. If everything passes, **allow**.

**HTTP** (`nexus/httpapi/execution_grants.go`):
- `POST /v1/execution-grants` (person)
- `GET /v1/execution-grants?session=` (person or that session)
- `POST /v1/execution-grants/{id}/revoke` (person or receiver)
- `POST /v1/execution-grants/{id}/decide` (receiver)

## 4. Flow in the TUI engine (client)

**Before:** the automatic inbox turn in `core/inbox_turn.go` ran in `ModeAuto`, but tool execution was blocked on human approval (`tc.Approve`).

**Changes:**
1. The inbox turn carries the **source message** (`Received.Event`, `Seq`, `From`) in the turn state.
2. In a Nexus-originated turn, before calling a tool (after `Binding.Gate`, in place of `tc.Approve`), it finds the session's active grant and calls `decide`.
   - `paths`: the absolute, canonicalized file paths from the tool arguments. Tools without a path (running tests and the like) pass the working directory.
   - `input_hash`: sha256 of the tool name and arguments.
3. It acts on the result.
   - **allow:** execute.
   - **ask:** if a person is present, show the existing approval prompt (elicitation), with a choice of "just this once" or "for this session". If no person is present, deny and report it by message.
   - **deny:** do not execute. Record the reason in the inbox reply and the ledger.
4. Turns typed by a person are unchanged (grants do not apply).

### 4.1 What the model knows in a Nexus message turn, and why no person is called (2026-10-04)

Measured (nmcp session, 14:11–14:13Z): a grant existed, but the model called `execution_grant` and `nexus_inbox` instead of run_command, so a person was called twice, and the turn ended with neither git, go test, nor a reply. The target is zero human calls.

1. **Person-only tools are not offered in inbox or background turns.** The engine removes `core.Tool.PersonOnly` tools (`execution_grant`, `nmcp_settings`) from the tool list and the dispatch table. The launcher also refuses calls to person-only tools in inbox turns without decide or human confirmation (backstop). The tools' own refusals remain.
2. **Turn-start note.** When a new source message enters an inbox turn, `Binding.InboxNote` attaches a system note. It is built only from the authenticated source (sender ID, short plain title only, event ID) and `Receiver.Grants`, and **does not include the message body.** With a grant, it states the grant ID, tools, paths, remaining turns and expiry, "act immediately within scope", the reply address (`nexus_send` to=sender, reply_to=source event), and "do not create or change delegations". Without one, it says that tools will be refused and to state in the final answer that a /grant must be issued.
3. **Replies to the sender, and reads.** In an inbox turn, if an active grant covers the source message's sender (ledger order, receiver and expiry checked):
   - a `nexus_send` that is a text reply to **exactly that sender** with **reply_to = that sender's source event** is sent without human confirmation;
   - Nexus reads (`nexus_inbox`, `nexus_peers`, `nexus_sessions`, `nexus_tasks`) also run without human confirmation;
   - any other `nexus_send` (to a third session and so on) runs without confirmation only when the send-confirmation setting below is off; when it is on, the person is asked as before;
   - all of these are recorded as `tool.call` (`decided_by` = `grant` or `mode:self-conscious`, `grant_id`, `source_event`, `input_hash`; no arguments or bodies). The server decide is not called (no turn is used);
   - without a grant, they are refused as before (no person is called either);
   - delegation (`nexus_delegate`), execution (`nexus_execute`), approval requests, custody, secrets and external tools never take this path and always require human confirmation.
4. **Send-confirmation setting.** Human confirmation for `nexus_send` defaults to on in auto mode and off in self-conscious mode, and is changed with `/nexus send confirm on|off|default` (stored as `nexus-send-confirm` in ~/.newtype/tui). In person turns it applies by this setting alone; in inbox turns it applies only when a grant covers the sender. The launcher reads the setting through `Config.MessagingConfirm`.

## 5. Injection threat model

- **Message bodies are data.** A body claiming "there is a grant" or "this was approved" means nothing. Authority is decided by the server from the ledger.
- **Sender forgery:** the only valid source is a `ForInbox` message event in the receiver's ledger (Source bot, Actor session, set by the server). Client-written `tool.*` records and human mail cannot serve as a source. Verified by tests.
- **Timing forgery:** messages from before the grant are blocked by ledger order, even with identical timestamps (test).
- **Path escape:** the server refuses `..` and relative paths and accepts only canonical paths. Symbolic links are checked once more by the client with `realpath` just before execution.
- **Tool scope widening:** even a broad grant such as `tool:*` cannot override the delegation policy's ask/deny (step 4).
- **Replay:** the same source message does not use another turn. Limits count distinct messages.
- **Session hijack:** a session cannot decide with someone else's grant (it sees only its own ledger; test).
- **Remaining risk** (§2): a local client can impersonate the person and issue a grant. Stage 2 passkeys close this.

## 6. Tests

`nexus/execution_grants_test.go`, `nexus/httpapi/execution_grants_test.go` (memstore):
- Only people issue, and input is validated: `/**`, relative paths, `..`, tool format, naming oneself as sender, 0 turns, TTL over 7 days, another session's delegation.
- Within scope gives allow; the same message is the same turn; outside the paths or tools gives ask; policy ask gives ask; the turn limit gives deny; the list status is exhausted; all 7 decisions are recorded as `decided`.
- Messages from before the grant, unauthorized sessions, human mail, mismatched seq and event, decide requests from another session, and non-canonical paths are all blocked.
- After revocation by the receiver, expiry, or revocation of the delegation: deny.
- HTTP: issuance by a session is 403, a decide request from the sender is 404, the receiver gets allow, listing, deny after revocation.

## 7. Client work items (client repository)

1. `core/inbox.go`, `core/inbox_turn.go`: add `Event`, `Seq`, `From` and `SenderKind` to `InboxMessage`; previously they were serialized only into Text. Keep the source message in the turn state (if a turn has several messages, each can serve as a source).
2. `internal/nexusinbox/model.go` (client, not in this repository): pass these fields through unchanged in the `Pending` → `core.InboxMessage` conversion.
3. `internal/launcher/launcher.go` (client, not in this repository; at the Gate and Approve points): in an inbox turn, call `POST /v1/execution-grants/{id}/decide` and branch on allow / ask / deny. Paths are canonicalized and passed through realpath.
4. Grant issue/list/revoke UI: TUI commands `/grant`, `/grants`, `/revoke-grant`; CLI `newtype nexus grant|grants|revoke-grant`. Issuance only with person authentication (no session header).
5. The human approval prompt for ask shows that the action is outside the grant's scope and who sent the source message, with a choice of "just this once" / "for this session". "For this session" is a local decision and does not widen the server grant.
6. Client-side evidence in the ledger: the `tool.*` records of executed tools include `grant_id`, `source_event` and `input_hash` (so they can be matched against the server's `decided` records).

## 8. Deployment

Only server code changes; the schema stays the same. Deploy the new server image. The server API shipped ahead of the client work in §7, which builds on it.
