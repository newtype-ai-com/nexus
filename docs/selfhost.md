# Running your own Nexus (self-host)

Newtype can run against **your own Nexus server** instead of `lic.newtype-ai.com`. This document describes how, from start to finish. Only the commands and outputs that were actually run on 2026-10-05 on a Mac (Docker Desktop 29.2, arm64) are marked "verified"; anything not verified is marked **(not verified)**.

Some client and server messages are printed in Korean. In the outputs below they are shown in English translation and marked *(translated)*.

Kit: `deploy/selfhost/`

| File | Purpose |
|---|---|
| `compose.yaml` | PostgreSQL 17 (pinned by digest) + nexus + optional Caddy (TLS, profile `tls`) |
| `Dockerfile`, `Dockerfile.dockerignore` | Builds the nexus image from this repository (static Go binary → distroless/static, uid 65532) |
| `.env.example` | Every required and optional variable, and how to generate the secrets (`openssl rand`) |
| `Caddyfile` | Public HTTPS reverse proxy (automatic ACME certificates) |
| `dev/` | **Local trial only**: a throwaway CA, a mail sink that logs mail instead of sending it through Resend, a Linux client container |

## 0. Overview

```
internet ──443──> Caddy ──> nexus:8080 ─┐ (same network namespace)
                                        └─ 127.0.0.1:5432 postgres
host 127.0.0.1:${NEXUS_HTTP_PORT:-8080} ──> nexus:8080   (checks and local access)
```

- nexus shares the network namespace of the postgres container (`network_mode: service:postgres`). The database therefore listens **only on loopback (127.0.0.1)** and is not exposed even on the compose network. The server requires `sslmode=verify-full` (verified TLS) and port 5432 for any non-loopback database, so for a database on the same host this is the simplest setup. SCRAM authentication stays on (`NEXUS_DB_REQUIRE_SCRAM=1`, `--auth-host=scram-sha-256`).
- To use an external managed Postgres (Supabase and the like), set `DATABASE_URL` to `postgres://…:5432/…?sslmode=verify-full&sslrootcert=/path/ca.crt` and remove `NEXUS_ALLOW_LOCAL_DB` **(not verified: not tested with this kit)**.
- The nexus HTTP port is published only on `127.0.0.1`, from the postgres service that owns the shared namespace. Public exposure goes only through Caddy or a tunnel.

## 1. Prerequisites

- Docker Engine + Compose v2 (`docker compose version`), about 1 GB free for the image build.
- To connect remote clients (newtype on other computers, Claude Code remote MCP): one domain, HTTPS for that name (Caddy below or a Cloudflare tunnel), ports 80/443.
- **Mail provider (Resend API key) — optional if the owner is the only user**: the owner can be created without mail using an `enrol-owner` code (§4-A). Enrolment of other people, user admission approval, token increases and remote MCP mail consent need mail, and mail is sent only through the Resend HTTP API (§8 G3). However, enrolment settings are still not enabled while `RESEND_API_KEY` and `MAIL_FROM` are empty, so when starting without mail, put any string in them (for example `placeholder-not-used`). Then only the steps that need mail fail, with `gate: mail_unavailable`. Resend's test sender `onboarding@resend.dev` can send only to the Resend account owner's address **(not verified: no mail was sent through real Resend; locally this was checked with the mail sink)**.
- The `newtype` client accepts `https://` origins and, for development, loopback `http://127.0.0.1:port`, `http://localhost:port` and `http://[::1]:port`. Any other http origin is refused.

## 2. Installation (verified)

```sh
cd deploy/selfhost
cp .env.example .env && chmod 600 .env
# Generate the secrets yourself and paste them into .env (never leave the output anywhere).
openssl rand -hex 32      # POSTGRES_PASSWORD (hex, because it goes into a URL)
openssl rand -base64 32   # SEAL_MASTER
openssl rand -base64 32   # DELEGATION_SIGNING_KEY
openssl rand -hex 32      # ADMIN_TOKEN (optional, at least 32 characters)
# BASE_URL / SEAL_ISSUER / NEXUS_MCP_ISSUER = https://<your-domain>
# NEXUS_OWNER_EMAIL = ENROL_ALLOW = <owner email>, RESEND_API_KEY, MAIL_FROM (placeholder strings are fine if the owner is the only user, §4-A)
```

```sh
docker compose build nexus
docker compose up -d postgres
docker compose run --rm nexus migrate     # always, before the first start
docker compose up -d nexus
curl -fsS http://127.0.0.1:8080/v1/health
```

Verified output:

```
$ docker compose run --rm --no-deps nexus serve        # starting before migrate
nexus: schema mismatch; run explicit migration
$ docker compose run --rm nexus migrate
Nexus and Gate migrations complete
$ docker compose run --rm nexus migrate                 # running it again is the same (idempotent)
Nexus and Gate migrations complete
$ docker compose logs nexus
nexus: mode=serve enrolment=true model=false sealing=true owner_configured=true owner_only=true model_count=0 model_protocol=disabled
Nexus server listening
$ curl -sS http://127.0.0.1:18480/v1/health
{"enrolment_schema":4,"gate_schema":1,"nexus_schema":9,"ok":true}
```

**Upgrades do not migrate.** After building or pulling a new image, always:

```sh
docker compose build nexus            # or a new NEXUS_IMAGE
docker compose stop nexus
docker compose run --rm nexus migrate
docker compose up -d nexus
```

If you skip a step, nexus prints `schema mismatch; run explicit migration` and keeps restarting (the data is not changed).

## 3. Public HTTPS

### Caddy (included in the kit)

Set `NEXUS_DOMAIN=nexus.example.com` in `.env`, point DNS A/AAAA at this host, open 80/443, then:

```sh
docker compose --profile tls up -d caddy
curl -fsS https://nexus.example.com/v1/health
```

Caddy obtains the certificate through ACME **(not verified with public DNS; the same Caddy configuration was verified at `https://nexus.localtest` with a certificate from the local throwaway CA)**. `flush_interval -1` is set so that streams (`/v1/sessions/*/stream`, `/mcp`) are not buffered.

### Cloudflare tunnel (not verified)

Attaching the loopback port to a tunnel, as in `cloudflared tunnel --url http://127.0.0.1:8080`, gives HTTPS without Caddy. Nexus trusts `CF-Connecting-IP` only on requests coming from loopback, so when cloudflared runs on the host (loopback), per-IP rate limits work with the real client IP. Behind Caddy, every request appears to come from Caddy's IP (§8 G6).

## 4. Creating the owner

The owner is determined by a single server setting, `NEXUS_OWNER_EMAIL`. Every owner-only feature (user admission approval, monthly token increases, remote MCP mail consent and default model change approval in `nexus approvals`, the default model allow list) follows this address. If it is empty or malformed, owner features are off (they are not opened to everyone). Requirements: `NEXUS_OWNER_EMAIL` and `ENROL_ALLOW` set to the same address in `.env`, and `BASE_URL` an https origin.

### 4-A. Without mail: `enrol-owner` (verified)

The server operator creates a single-use code, and the owner enrols with that code on their own computer.

- Turning it on: the server default is off; the self-host kit's `.env.example` turns it on with `NEXUS_OWNER_CODE=1` (requires `NEXUS_OWNER_EMAIL`). After the owner has enrolled, set it to `0` and restart with `docker compose up -d nexus`. When it is off, the code path returns 404 and `enrol-owner` refuses with `enrol-owner is off; set NEXUS_OWNER_CODE=1`. The production server (`lic.newtype-ai.com`) does not turn it on (mail enrolment only).
- Code: 15 minutes, single use, for the configured owner address only. Only one live code exists per owner; creating a new one invalidates the previous one. It is counted separately from the "3 pending per address" limit of mail enrolment (it cannot be blocked through the public `POST /v1/enrol`).
- Logs: Nexus never writes the code anywhere. Container stdout follows the Docker log driver, so the kit's `enrol-owner` service uses `logging: {driver: none}`. When the code is redeemed, Nexus leaves an audit line containing only the enrolment id (`"type":"owner_code_redeemed"`) and, if mail is configured, sends the owner a notice that owner credentials were issued with an operator code (no code or link).
- Getting a code is subject to the same rate limit as starting an enrolment (`POST /v1/enrol`), 30 per minute.

Server (operator):

```sh
docker compose run --rm enrol-owner
```

```
One-time owner code for boss@selfhost.test (single use, expires 2026-10-05T07:14:10Z):
eoc_<64 hex>

On the owner's computer:
  newtype auth enrol --gate-url https://nexus.localtest --code
  (paste the code at the hidden prompt; never as a command argument)
```

On the owner's computer (a person carries the code over by hand and never passes it as a command argument — it would remain in `ps` and the shell history):

```sh
newtype auth enrol --gate-url https://nexus.example.com --code
# Paste the code at the hidden prompt. When not on a terminal, it reads one line from stdin.
```

Verified output (local trial, kit + loopback http, mail key set to a placeholder string):

```
$ … | newtype auth enrol --gate-url http://127.0.0.1:18482 --code
Enrolment credentials saved · no secrets printed                                  (translated)
$ … | newtype auth enrol --gate-url http://127.0.0.1:18482 --code --credential-dir <another dir>   # the same code again
gate: not_found
$ newtype auth status --credential-dir …
Gate: valid
$ docker compose logs nexus | tail -1
{…,"established":{"outcome":"credentials_issuable"},…,"request_id":"eno_…","type":"owner_code_redeemed"}
$ docker compose logs mailsink        # dev overlay
{"to": ["boss@selfhost.test"], "subject": "Newtype owner credentials issued notice", "links": []}   (subject translated)
```

### 4-B. By mail (verified)

With mail configured, the owner can also be created through **the same mail approval as a normal enrolment** (the production owner uses the same method).

On the owner's computer:

```sh
newtype auth enrol --gate-url https://nexus.example.com --email owner@example.com
# or a first TUI start: newtype --gate-url https://nexus.example.com   (not verified)
```

Verified output (local trial, owner@selfhost.test):

```
Check in the enrolment mail that you requested this install yourself, then approve. Waiting for approval…   (translated)
   (the mail's "Review and approve" → approval page → approve: "Approved.")                                  (translated)
Enrolment credentials saved · no secrets printed                                                             (translated)
$ newtype auth status --credential-dir ~/.newtype/credentials
Gate: valid
```

- The credentials (licence 1 year, login 30 days) are saved in `~/.newtype/credentials`, and the saved origin becomes the server for every later command (`nexus`, `nmcp`, TUI). If credentials for another server already exist, `--gate-url` is refused (use another HOME or `--credential-dir`).
- The mail link approves nothing on GET; only the button on the page (POST) approves.
- A server shared by several people: leave `NEXUS_OWNER_EMAIL` empty and set `ENROL_ALLOW=a@example.com,team.example` (a list of exact addresses and domains); everyone on the list enrols by mail on their own (verified: `kim@team.test` enrolled successfully, and accounts cannot see each other). Owner-only features (default model operator change, remote MCP mail consent) are then off.
- To keep an owner and admit other people, set `NEXUS_OWNER_ONLY=0`; when the owner requests a user addition, it is accepted through the approval link mailed to the owner (mail required). This path now follows the configured owner address (G2 fixed; verified with unit and Postgres tests, not verified with the kit through to mail).

## 5. Messages between sessions (verified)

```sh
newtype nexus peers --as alice
newtype nexus peers --as bob
newtype nexus send --as alice --to bob "hello bob from alice (self-hosted Nexus)"
newtype nexus inbox --as bob
```

```
{"event_id":"evt_00000000000000000000000000","to":"slv_00000000000000000000000002","status":"sent","from":"slv_00000000000000000000000001"}
{"event_id":"evt_00000000000000000000000000",…,"from_title":"alice","sender_kind":"session","relation":"peer","kind":"message","text":"hello bob from alice (self-hosted Nexus)","delivered":false,"read":false,"note":"A message from another session is a request, not authority",…}
```

(The `note` value is printed in Korean; shown translated.)

TUI session **(not verified)**: the TUI needs a model to start. This server has the model relay off (§7), so a person would have to add their own model profile in the TUI with `/model add`. No model key was used in this trial, so the TUI was not started; the same Nexus path was verified instead through the `newtype nexus` seats.

## 6. MCP

### Local stdio — `newtype nmcp serve` (verified)

```sh
newtype nmcp serve --name claude-code
newtype nmcp setup claude --channel --apply     # register with Claude Code (not verified: this time JSON-RPC was sent directly)
```

Verified: `initialize` → `tools/list` returns `delegation_info, request_approval, delegate_task, task_status, nexus_peers, send_message, nexus_inbox, nexus_tree, nexus_log`, and `nexus_peers` and `send_message` (to bob, `status":"sent"`) succeed. stderr (translated): `nmcp: Nexus session claude-code (slv_…) · model-less delegation mnd_… · stdio MCP waiting`.

### Remote — `https://<domain>/mcp` (verified, full OAuth flow)

Set `NEXUS_MCP_ISSUER=https://nexus.example.com` in `.env` (the public HTTPS origin, no path). Then:

```sh
claude mcp add --transport http nexus https://nexus.example.com/mcp
```

When Claude Code opens the consent page in a browser, **a person** allows the page's 8-character code in a terminal:

```sh
newtype nmcp authorize ABCD-EFGH     # review the preview, then y
```

Local verification (the same sequence with curl instead of Claude Code): `/oauth/register` → `/oauth/authorize` (code shown) → `newtype nmcp authorize CODE` → `/oauth/authorize/status` = `approved` → `/oauth/token` (`token_type: Bearer`, `expires_in: 3600`, `scope: nexus:connect`) → `POST /mcp initialize` 200 + `Mcp-Session-Id` → `tools/call send_message` succeeds. `POST /mcp` without a token **returning 401 is expected**:

```
HTTP/2 401
www-authenticate: Bearer resource_metadata="https://nexus.localtest/.well-known/oauth-protected-resource/mcp", scope="nexus:connect"
```

Claude Code itself was not connected **(not verified: needs a public certificate)**. The mail consent path needs the approval server (`nexus approvals`), which mails the configured `NEXUS_OWNER_EMAIL` **(not verified: the kit does not include the approval server)**.

## 7. Optional features

- **Model relay**: off by default. Each person uses their own model profile in the client. To relay one shared model, set `MODEL_UPSTREAM` (full OpenAI-compatible URL), `MODEL_API_KEY`, `MODEL_NAMES`, `MODEL_TOKEN_CEILING` and `MODEL_MAX_OUTPUT` together (for Azure Foundry see `.env.example`) **(not verified)**.
- **Sealing**: set `SEAL_MASTER`, `DELEGATION_SIGNING_KEY`, `SIGNING_KID` and `SEAL_ISSUER` together. Used to sign delegations and receipts and to seal secrets. If `SEAL_MASTER` is lost, sealed values cannot be opened. Keep it offline, separately. (This trial was verified with sealing on.)
- **Default model operator change and approval mail server (`nexus approvals`)**: enabled by the configured `NEXUS_OWNER_EMAIL` (G2 fixed). Not included in the kit **(not verified)**.
- **Client release distribution (`NEXUS_RELEASES_DIR`)**: when empty, `/llm.txt`, `/install.sh` and `/v1/releases/*` return 404 (verified). A self-host without signing keys gets the client through the official install path.

### Backups (verified)

```sh
(umask 077; docker compose exec -T postgres pg_dump -U nexus -d nexus -Fc > nexus-$(date +%F).dump)
# Restore test (separate database):
docker compose exec -T postgres createdb -U nexus nexus_restore
docker compose exec -T postgres pg_restore -U nexus -d nexus_restore --no-owner < nexus-YYYY-MM-DD.dump
```

Verified: a 53 KB dump with 36 tables of data; in the restored database, 2 `gate_credentials` rows and schema 9 intact. Dumps contain accounts, messages and credential verifiers, so keep them at `chmod 600` and store them somewhere encrypted (for example, dump after `umask 077`). Keep `.env` (especially `SEAL_MASTER` and `DELEGATION_SIGNING_KEY`) as well, but in **a different place** from the dumps.

## 8. Gaps that block self-hosting today, and small proposed fixes

Status: G1, G2, G4, G5 and G10 are fixed. The rest are proposals.

| # | Gap | Impact | Small fix |
|---|---|---|---|
| G1 | No published server image. ~~The repository's `deploy/Dockerfile` failed to build~~ | You must build it yourself | **Fixed**: `deploy/Dockerfile` builds like the kit with `COPY . .` + a root `.dockerignore` (allowing only the packages cmd/nexus uses) (verified with `docker build -f deploy/Dockerfile .`). Remaining: publish multi-arch images with digests to GHCR for every tag |
| G2 | ~~The owner policy was tied to a fixed address~~ | — | **Fixed**: user admission approval, monthly token increases and `nexus approvals` all follow `NEXUS_OWNER_EMAIL`. An empty or invalid value means no owner features. The production server sets the same address, so its behavior is unchanged |
| G3 | Enrolment of anyone other than the owner requires mail, and mail is Resend only (fixed to `https://api.resend.com/emails`). Enrolment settings are not enabled without mail keys | The owner is solved by G4; other people need a mail provider. Starting without mail needs placeholder keys | Add an SMTP implementation to the `Mailer` interface (`SMTP_URL`), and allow enrolment settings without mail keys (code only) |
| G4 | ~~No official way to create the owner without mail~~ | — | **Fixed**: with `NEXUS_OWNER_CODE=1`, `enrol-owner` prints a single-use 15-minute code for the configured owner (one per owner) only to the operator's terminal → `newtype auth enrol --code` (hidden prompt/stdin). Reuses the existing enrolment tables (no schema change); tokens are claimed by the client as before (§4-A) |
| G5 | ~~The client accepted only `https://` origins~~ (macOS still does not honor `SSL_CERT_FILE`) | Local trials now work with loopback http | **Fixed**: only `http://127.0.0.1`, `http://localhost` and `http://[::1]` (any port) are allowed for development; everything else must be https |
| G6 | The real client IP is obtained only under a Cloudflare assumption (`CF-Connecting-IP`, and only when the peer is loopback) | Behind Caddy or nginx every request has the single proxy IP → per-IP limits apply to everyone together | Trust the last hop of `X-Forwarded-For` only with a setting such as `NEXUS_TRUSTED_PROXIES=172.16.0.0/12` |
| G7 | The remote MCP browser Origin allow list is fixed to claude.ai/claude.com | Other web clients cannot connect from a browser (server-to-server clients are unaffected) | A `NEXUS_MCP_ORIGINS` setting |
| G8 | A non-loopback database is forced to `verify-full` + port 5432, and a same-host database only via `NEXUS_ALLOW_LOCAL_DB=1` (a name that looks "development only") | The kit solves this by sharing the namespace, but the name is misleading | Rename to `NEXUS_DB_LOOPBACK=1` (old name kept as an alias) |
| G9 | The image has no healthcheck tool (distroless) | No compose healthcheck for nexus | Add a `nexus health` subcommand (checks 127.0.0.1:PORT/v1/health), enabling `healthcheck: ["CMD","/nexus","health"]` |
| G10 | ~~No public repository~~ | — | **Fixed**: `https://github.com/newtype-ai-com/nexus` (Apache-2.0) |

## 9. Local trial (reproducing the "verified" items of this document)

Only Docker is needed. Nothing goes out, and ports are opened only on 127.0.0.1. Mail is received by a mail sink posing as `api.resend.com` and printed to its log, and the client runs in a Linux container (on Linux, Go honors `SSL_CERT_FILE`, so the host trust store is not touched).

```sh
cd deploy/selfhost
export COMPOSE_FILE=compose.yaml:dev/compose.dev.yaml
./dev/gen-dev-certs.sh
# Client: place the Linux binary from the signed distribution (https://lic.newtype-ai.com/llm.txt) at dev/bin/newtype
cp .env.example .env    # values: BASE_URL=https://nexus.localtest (the dev overlay pins BASE_URL, NEXUS_MCP_ISSUER and SEAL_ISSUER
                        #   to this value, and the mail sink does not start if the BASE_URL in .env differs),
                        # owner=ENROL_ALLOW=owner@selfhost.test, RESEND_API_KEY=any string, secrets from openssl
docker compose build nexus && docker compose up -d postgres
docker compose run --rm nexus migrate
docker compose up -d nexus caddy
docker compose run --rm client auth enrol --gate-url https://nexus.localtest --email owner@selfhost.test \
  --credential-dir /home/client/.newtype/credentials &
docker compose logs mailsink            # {"to": [...], "subject": "Newtype install/login approval" (translated), "links": ["https://nexus.localtest/enrol/verify?t=vfy_…"]}
curl --cacert dev/certs/ca.crt --connect-to nexus.localtest:443:127.0.0.1:8443 -X POST '<that link>'
docker compose run --rm -T client nexus peers --as alice
docker compose --profile tls --profile client down -v   # when done, remove the volumes too
```

(macOS zsh does not split a variable on spaces into separate words, so use the `COMPOSE_FILE` environment variable.)

The throwaway CA from `gen-dev-certs.sh` can sign only two names, `nexus.localtest` and `api.resend.com` (nameConstraints, pathlen 0), and its key is deleted right after signing. Keys are 0600, and each container mounts only its own certificate and key files, read-only. To test without TLS, you can also run `newtype auth enrol --gate-url http://127.0.0.1:8080 --code` directly on the Mac (loopback http is allowed, G5).

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| nexus keeps restarting with `schema mismatch; run explicit migration` | migrate was not run after the first start or an upgrade → `docker compose stop nexus && docker compose run --rm nexus migrate && docker compose up -d nexus` |
| `nexus: database connection failed (…)` | `POSTGRES_PASSWORD` is not hex (broken URL), or postgres is not healthy yet. If the volume already exists, changing the password leaves the old value in the database |
| `DATABASE_URL requires sslmode=verify-full without fallback` | A non-loopback database without TLS verification. On the same host, use the kit's shared namespace; for an external database, `sslmode=verify-full&sslrootcert=…` |
| `nexus: invalid enrolment configuration` | `BASE_URL` is not an https origin, `ADMIN_TOKEN` is shorter than 32 characters, `ENROL_ALLOW` is malformed (domains are `example.com` without `@`), or an owner is set but `ENROL_ALLOW` ≠ owner |
| `enrolment requires BASE_URL, ENROL_ALLOW, RESEND_API_KEY and MAIL_FROM` | If any one of the four is set, all four are required |
| Client `gate: mail_unavailable` | Resend refused (key or sender domain). Check the logs in the Resend dashboard |
| Client `gate: enrol_not_allowed` | The address differs from `ENROL_ALLOW` (in owner mode, from the owner) |
| `newtype auth enrol --code` gives `gate: not_found` | The code was already used, 15 minutes have passed, it was replaced by a newer code, the server's `NEXUS_OWNER_CODE` is off, or `NEXUS_OWNER_EMAIL` is a different address. The operator runs `docker compose run --rm enrol-owner` again |
| `enrol-owner is off; set NEXUS_OWNER_CODE=1` | Add `NEXUS_OWNER_CODE=1` to `.env` and restart with `docker compose up -d nexus` |
| nexus cannot write to `/data` (model call budget file and so on) | This kit's image creates an empty `/data` owned by uid 65532, and a new `nexusdata` volume inherits that ownership. A volume already created by an earlier image stays owned by root: after `docker compose down`, run `docker volume rm <project>_nexusdata` (if you do not need its files) or `docker run --rm -v <project>_nexusdata:/d postgres:17 chown 65532:65532 /d` |
| `gate: explicit HTTPS origin required` | `--gate-url` is not https and not loopback (`127.0.0.1`, `localhost`, `[::1]`) http either |
| `--gate-url is for enrolment only; credentials for another Gate are already saved` | Credentials for another server already exist → use another `HOME` or `--credential-dir` |
| `POST /mcp` returns 401 | Expected for a request without a token. Claude Code starts OAuth from this response |
| `/llm.txt` 404 | `NEXUS_RELEASES_DIR` is empty (expected) |
| The remote MCP consent page keeps waiting | A person must run `newtype nmcp authorize CODE` to proceed (mail consent only exists with the approval server `nexus approvals`) |
