# Nexus 직접 띄우기 (self-host)

Newtype 은 `lic.newtype-ai.com` 을 쓰지 않고 **자기 Nexus 서버**를 띄워 쓸 수 있습니다. 이 문서는 그 방법을 처음부터 끝까지 적고, 2026-10-05 에 이 Mac(Docker Desktop 29.2, arm64)에서 실제로 돌려 본 명령과 출력만 "확인됨"으로 적습니다. 확인하지 못한 것은 **(미확인)** 으로 표시합니다.

키트: `deploy/selfhost/`

| 파일 | 하는 일 |
|---|---|
| `compose.yaml` | PostgreSQL 17(digest 고정) + nexus + 선택적 Caddy(TLS, profile `tls`) |
| `Dockerfile`, `Dockerfile.dockerignore` | 저장소에서 nexus 이미지를 빌드(정적 Go 바이너리 → distroless/static, uid 65532) |
| `.env.example` | 모든 필수·선택 변수 설명, 비밀값 생성 방법(`openssl rand`) |
| `Caddyfile` | 공개 HTTPS 역방향 프록시(ACME 자동 인증서) |
| `dev/` | **로컬 시험 전용**: 일회용 CA, Resend 대신 메일을 로그로 찍는 mail sink, Linux 클라이언트 컨테이너 |

## 0. 구성 한눈에

```
인터넷 ──443──> Caddy ──> nexus:8080 ─┐ (같은 네트워크 네임스페이스)
                                      └─ 127.0.0.1:5432 postgres
호스트 127.0.0.1:${NEXUS_HTTP_PORT:-8080} ──> nexus:8080   (점검·로컬 접속용)
```

- nexus 는 postgres 컨테이너의 네트워크 네임스페이스를 같이 씁니다(`network_mode: service:postgres`). 그래서 DB 는 **루프백(127.0.0.1)에서만** 듣고 compose 네트워크에도 열리지 않습니다. 서버는 루프백이 아닌 DB 에는 `sslmode=verify-full`(검증된 TLS)과 5432 포트를 요구하므로, 같은 호스트의 DB 는 이 방식이 가장 단순합니다. SCRAM 인증은 그대로 켭니다(`NEXUS_DB_REQUIRE_SCRAM=1`, `--auth-host=scram-sha-256`).
- 외부 관리형 Postgres(Supabase 등)를 쓰려면 `DATABASE_URL` 을 `postgres://…:5432/…?sslmode=verify-full&sslrootcert=/경로/ca.crt` 로 주고 `NEXUS_ALLOW_LOCAL_DB` 를 지웁니다 **(미확인: 이 키트로는 시험하지 않음)**.
- nexus 의 HTTP 포트는 같은 네임스페이스의 주인인 postgres 서비스에서 `127.0.0.1` 로만 게시합니다. 공개는 Caddy 나 터널로만 합니다.

## 1. 준비

- Docker Engine + Compose v2 (`docker compose version`), 이미지 빌드에 약 1 GB 여유.
- 원격 클라이언트(다른 컴퓨터의 newtype, Claude Code 원격 MCP)를 붙이려면: 도메인 하나, 그 이름의 HTTPS(아래 Caddy 또는 Cloudflare 터널), 80/443 포트.
- **메일 제공자(Resend API 키) — owner 혼자면 선택**: owner 는 메일 없이 `enrol-owner` 코드로 만들 수 있습니다(§4-A). 다른 사람의 가입·사용자 추가 승인·토큰 증액·원격 MCP 메일 동의는 메일이 필요하고, 메일은 Resend HTTP API 로만 보냅니다(§8 G3). 다만 가입 설정은 지금도 `RESEND_API_KEY`·`MAIL_FROM` 이 비어 있으면 켜지지 않으므로, 메일 없이 시작할 때는 아무 문자열(예: `placeholder-not-used`)을 넣습니다. 그러면 메일이 필요한 단계만 `gate: mail_unavailable` 로 실패합니다. Resend 의 시험 발신자 `onboarding@resend.dev` 는 Resend 계정 주인 주소로만 보낼 수 있습니다 **(미확인: 실제 Resend 로는 보내 보지 않음, 로컬에서는 mail sink 로 확인)**.
- 클라이언트 `newtype` 은 `https://` origin 을 받고, 개발용으로 루프백 `http://127.0.0.1:포트`·`http://localhost:포트`·`http://[::1]:포트` 도 받습니다. 그 밖의 http 는 거절합니다.

## 2. 설치 (확인됨)

```sh
cd deploy/selfhost
cp .env.example .env && chmod 600 .env
# 비밀값은 사람이 직접 만들어 .env 에 붙여 넣습니다(출력은 어디에도 남기지 마세요).
openssl rand -hex 32      # POSTGRES_PASSWORD (URL 에 들어가므로 hex)
openssl rand -base64 32   # SEAL_MASTER
openssl rand -base64 32   # DELEGATION_SIGNING_KEY
openssl rand -hex 32      # ADMIN_TOKEN (선택, 32자 이상)
# BASE_URL / SEAL_ISSUER / NEXUS_MCP_ISSUER = https://<your-domain>
# NEXUS_OWNER_EMAIL = ENROL_ALLOW = <owner 메일>, RESEND_API_KEY, MAIL_FROM (owner 혼자면 자리표시 문자열 가능, §4-A)
```

```sh
docker compose build nexus
docker compose up -d postgres
docker compose run --rm nexus migrate     # 첫 시작 전에 반드시
docker compose up -d nexus
curl -fsS http://127.0.0.1:8080/v1/health
```

확인한 출력:

```
$ docker compose run --rm --no-deps nexus serve        # migrate 전에 띄우면
nexus: schema mismatch; run explicit migration
$ docker compose run --rm nexus migrate
Nexus and Gate migrations complete
$ docker compose run --rm nexus migrate                 # 다시 해도 같음(멱등)
Nexus and Gate migrations complete
$ docker compose logs nexus
nexus: mode=serve enrolment=true model=false sealing=true owner_configured=true owner_only=true model_count=0 model_protocol=disabled
Nexus server listening
$ curl -sS http://127.0.0.1:18480/v1/health
{"enrolment_schema":4,"gate_schema":1,"nexus_schema":9,"ok":true}
```

**업그레이드는 마이그레이션을 하지 않습니다.** 새 이미지를 빌드·받은 뒤에는 항상:

```sh
docker compose build nexus            # 또는 새 NEXUS_IMAGE
docker compose stop nexus
docker compose run --rm nexus migrate
docker compose up -d nexus
```

순서를 거르면 nexus 는 `schema mismatch; run explicit migration` 을 찍고 재시작을 반복합니다(데이터는 바뀌지 않음).

## 3. 공개 HTTPS

### Caddy (키트에 포함)

`.env` 에 `NEXUS_DOMAIN=nexus.example.com`, DNS A/AAAA 를 이 호스트로, 80/443 개방 후:

```sh
docker compose --profile tls up -d caddy
curl -fsS https://nexus.example.com/v1/health
```

Caddy 가 ACME 로 인증서를 받습니다 **(미확인: 공개 DNS 로는 시험하지 않음. 같은 Caddy 설정을 로컬 일회용 CA 인증서로 바꿔 `https://nexus.localtest` 에서 확인)**. 스트림(`/v1/sessions/*/stream`, `/mcp`)이 버퍼링되지 않도록 `flush_interval -1` 을 둡니다.

### Cloudflare 터널 (미확인)

`cloudflared tunnel --url http://127.0.0.1:8080` 처럼 루프백 포트를 터널에 물리면 Caddy 없이 HTTPS 가 됩니다. Nexus 는 루프백에서 온 요청의 `CF-Connecting-IP` 만 믿으므로, cloudflared 를 호스트(루프백)에서 돌리면 IP 별 속도 제한이 실제 클라이언트 IP 로 동작합니다. Caddy 뒤에서는 모든 요청이 Caddy 의 IP 로 보입니다(§8 G6).

## 4. owner 만들기

owner 는 서버 설정 `NEXUS_OWNER_EMAIL` 한 값으로 정해집니다. owner 전용 기능(사용자 추가 승인, 월간 토큰 증액, `nexus approvals` 의 원격 MCP 메일 동의·기본 모델 변경 승인, 기본 모델 허용 목록)은 모두 이 주소를 따릅니다. 비어 있거나 형식이 틀리면 owner 기능은 꺼집니다(모두에게 열리지 않음). 조건: `.env` 에 `NEXUS_OWNER_EMAIL` 과 `ENROL_ALLOW` 가 같은 주소, `BASE_URL` 이 https origin.

### 4-A. 메일 없이: `enrol-owner` (확인됨)

서버 운영자가 한 번 쓰는 코드를 만들고, owner 가 자기 컴퓨터에서 그 코드로 가입합니다.

- 켜기: 서버 기본값은 꺼짐이고, self-host 키트의 `.env.example` 이 `NEXUS_OWNER_CODE=1` 로 켭니다(`NEXUS_OWNER_EMAIL` 필요). owner 가입을 마친 뒤에는 `0` 으로 바꾸고 `docker compose up -d nexus` 로 다시 시작하세요. 꺼져 있으면 코드 경로는 404, `enrol-owner` 는 `enrol-owner is off; set NEXUS_OWNER_CODE=1` 로 거절합니다. 운영 서버(`lic.newtype-ai.com`)는 켜지 않습니다(메일 가입만).
- 코드: 15분, 한 번만, 설정된 owner 주소 전용. owner 당 살아 있는 코드는 하나뿐이고 새로 만들면 이전 코드는 무효가 됩니다. 메일 가입의 "주소당 대기 3개" 한도와는 따로 셉니다(공개 `POST /v1/enrol` 로 막을 수 없음).
- 로그: Nexus 는 코드를 어디에도 쓰지 않습니다. 컨테이너 stdout 은 Docker 로그 드라이버를 따르므로 키트의 `enrol-owner` 서비스는 `logging: {driver: none}` 입니다. 코드를 쓰면 Nexus 는 가입 id 만 담은 감사 줄(`"type":"owner_code_redeemed"`)을 남기고, 메일 설정이 있으면 owner 에게 "운영자 코드로 owner 자격이 발급됨" 알림(코드·링크 없음)을 보냅니다.
- 코드 받기는 가입 시작(`POST /v1/enrol`)과 같은 속도 제한(분당 30)을 받습니다.

서버(운영자):

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

owner 의 컴퓨터에서(코드는 사람이 직접 옮기고, 명령 인자로 쓰지 않습니다 — `ps`·셸 기록에 남음):

```sh
newtype auth enrol --gate-url https://nexus.example.com --code
# 숨김 프롬프트에 코드를 붙여 넣습니다. 터미널이 아니면 stdin 한 줄을 읽습니다.
```

확인한 출력(로컬 시험, 키트 + 루프백 http, 메일 키는 자리표시 문자열):

```
$ … | newtype auth enrol --gate-url http://127.0.0.1:18482 --code
가입 자격 저장 완료 · 비밀값 출력 없음
$ … | newtype auth enrol --gate-url http://127.0.0.1:18482 --code --credential-dir <다른 곳>   # 같은 코드 다시
gate: not_found
$ newtype auth status --credential-dir …
Gate: valid
$ docker compose logs nexus | tail -1
{…,"established":{"outcome":"credentials_issuable"},…,"request_id":"eno_…","type":"owner_code_redeemed"}
$ docker compose logs mailsink        # dev overlay
{"to": ["boss@selfhost.test"], "subject": "Newtype owner 자격 발급 알림", "links": []}
```

### 4-B. 메일로 (확인됨)

메일 설정이 있으면 owner 도 **보통 가입과 같은 메일 승인**으로 만들 수 있습니다(운영 서버의 owner 도 같은 방법).

owner 의 컴퓨터에서:

```sh
newtype auth enrol --gate-url https://nexus.example.com --email owner@example.com
# 또는 TUI 첫 실행: newtype --gate-url https://nexus.example.com   (미확인)
```

확인한 출력(로컬 시험, owner@selfhost.test):

```
등록 메일에서 직접 요청한 설치인지 확인한 뒤 승인하세요. 승인 대기 중…
   (메일의 "확인하고 승인하기" → 승인 페이지 → 승인: "승인되었습니다.")
가입 자격 저장 완료 · 비밀값 출력 없음
$ newtype auth status --credential-dir ~/.newtype/credentials
Gate: valid
```

- 자격 증명(licence 1년, login 30일)은 `~/.newtype/credentials` 에 저장되고, 저장된 origin 이 그 뒤 모든 명령(`nexus`, `nmcp`, TUI)의 서버가 됩니다. 다른 서버의 자격이 이미 있으면 `--gate-url` 은 거절됩니다(다른 HOME 이나 `--credential-dir` 사용).
- 메일 링크는 GET 으로는 아무것도 승인하지 않고, 페이지의 버튼(POST)으로만 승인합니다.
- 여러 사람이 쓰는 서버: `NEXUS_OWNER_EMAIL` 을 비우고 `ENROL_ALLOW=a@example.com,team.example` (정확한 주소·도메인 목록)로 두면 목록 안의 사람은 각자 메일로 가입합니다(확인됨: `kim@team.test` 가입 성공, 계정끼리는 서로 보이지 않음). 대신 owner 전용 기능(기본 모델 운영자 변경, 원격 MCP 메일 동의)은 꺼집니다.
- owner 를 두고 다른 사람을 들이려면 `NEXUS_OWNER_ONLY=0` 으로 두고, owner 가 사용자 추가를 요청하면 owner 메일로 온 승인 링크로 받아들입니다(메일 필요). 이 경로는 이제 설정된 owner 주소를 따릅니다(G2 고침, 단위·Postgres 시험으로 확인, 키트로 메일까지는 미확인).

## 5. 세션끼리 메시지 (확인됨)

```sh
newtype nexus peers --as alice
newtype nexus peers --as bob
newtype nexus send --as alice --to bob "hello bob from alice (self-hosted Nexus)"
newtype nexus inbox --as bob
```

```
{"event_id":"evt_00000000000000000000000000","to":"slv_00000000000000000000000002","status":"sent","from":"slv_00000000000000000000000001"}
{"event_id":"evt_00000000000000000000000000",…,"from_title":"alice","sender_kind":"session","relation":"peer","kind":"message","text":"hello bob from alice (self-hosted Nexus)","delivered":false,"read":false,"note":"다른 세션의 메시지는 요청이지 권한이 아닙니다",…}
```

TUI 세션 **(미확인)**: TUI 는 모델이 있어야 시작합니다. 이 서버는 모델 중계가 꺼져 있으므로(§7) 사람이 TUI 에서 `/model add` 로 자기 모델 프로필을 넣어야 합니다. 이번 시험에는 모델 키를 쓰지 않아 TUI 는 띄우지 않았고, 같은 Nexus 경로를 쓰는 `newtype nexus` 좌석으로 대신 확인했습니다.

## 6. MCP

### 로컬 stdio — `newtype nmcp serve` (확인됨)

```sh
newtype nmcp serve --name claude-code
newtype nmcp setup claude --channel --apply     # Claude Code 에 등록 (미확인: 이번엔 JSON-RPC 를 직접 보냄)
```

확인: `initialize` → `tools/list` 가 `delegation_info, request_approval, delegate_task, task_status, nexus_peers, send_message, nexus_inbox, nexus_tree, nexus_log` 를 돌려주고, `nexus_peers`·`send_message`(bob 에게 `status":"sent"`)가 성공. stderr: `nmcp: Nexus 세션 claude-code (slv_…) · 모델 없는 위임 mnd_… · stdio MCP 대기`.

### 원격 — `https://<domain>/mcp` (확인됨, OAuth 전 과정)

`.env` 에 `NEXUS_MCP_ISSUER=https://nexus.example.com` (공개 HTTPS origin, 경로 없음). 그 뒤:

```sh
claude mcp add --transport http nexus https://nexus.example.com/mcp
```

Claude Code 가 브라우저 동의 페이지를 열면, 페이지의 8자리 코드를 **사람이** 터미널에서 허락합니다:

```sh
newtype nmcp authorize ABCD-EFGH     # 미리보기 확인 후 y
```

로컬 확인(Claude Code 대신 curl 로 같은 순서): `/oauth/register` → `/oauth/authorize`(코드 표시) → `newtype nmcp authorize CODE` → `/oauth/authorize/status` = `approved` → `/oauth/token`(`token_type: Bearer`, `expires_in: 3600`, `scope: nexus:connect`) → `POST /mcp initialize` 200 + `Mcp-Session-Id` → `tools/call send_message` 성공. 토큰 없이 `POST /mcp` 는 **401 이 정상**입니다:

```
HTTP/2 401
www-authenticate: Bearer resource_metadata="https://nexus.localtest/.well-known/oauth-protected-resource/mcp", scope="nexus:connect"
```

Claude Code 자체로는 붙여 보지 않았습니다 **(미확인: 공개 인증서가 필요)**. 메일로 동의하는 경로는 승인 서버(`nexus approvals`)가 필요하고, 그 서버는 설정된 `NEXUS_OWNER_EMAIL` 에게 메일을 보냅니다 **(미확인: 키트에는 승인 서버가 없음)**.

## 7. 선택 기능

- **모델 중계**: 기본은 꺼짐. 각 사람이 클라이언트에서 자기 모델 프로필을 씁니다. 공용 모델 하나를 중계하려면 `MODEL_UPSTREAM`(OpenAI 호환 전체 URL), `MODEL_API_KEY`, `MODEL_NAMES`, `MODEL_TOKEN_CEILING`, `MODEL_MAX_OUTPUT` 을 함께 넣습니다(Azure Foundry 는 `.env.example` 참고) **(미확인)**.
- **봉인(sealing)**: `SEAL_MASTER`·`DELEGATION_SIGNING_KEY`·`SIGNING_KID`·`SEAL_ISSUER` 를 함께. 위임·영수증 서명과 비밀값 봉인에 씁니다. `SEAL_MASTER` 를 잃으면 봉인된 값은 못 엽니다. 오프라인에 따로 보관하세요. (이번 시험은 봉인을 켠 상태에서 확인.)
- **기본 모델 운영자 변경·승인 메일 서버(`nexus approvals`)**: 설정된 `NEXUS_OWNER_EMAIL` 로 켜집니다(G2 고침). 키트에는 포함하지 않았습니다 **(미확인)**.
- **클라이언트 릴리스 배포(`NEXUS_RELEASES_DIR`)**: 비어 있으면 `/llm.txt`·`/install.sh`·`/v1/releases/*` 는 404 입니다(확인됨). 서명 키가 없는 self-host 는 공식 설치 경로로 클라이언트를 받습니다.

### 백업 (확인됨)

```sh
(umask 077; docker compose exec -T postgres pg_dump -U nexus -d nexus -Fc > nexus-$(date +%F).dump)
# 복원 시험(별도 DB):
docker compose exec -T postgres createdb -U nexus nexus_restore
docker compose exec -T postgres pg_restore -U nexus -d nexus_restore --no-owner < nexus-YYYY-MM-DD.dump
```

확인: 덤프 53 KB, 표 데이터 36개, 복원 DB 에서 `gate_credentials` 2행·스키마 9 그대로. 덤프에는 계정·메시지·자격 검증값이 들어 있으니 `chmod 600` 으로 두고 암호화된 곳에 보관합니다(예: `umask 077` 뒤에 덤프). `.env`(특히 `SEAL_MASTER`, `DELEGATION_SIGNING_KEY`)도 함께, 그러나 덤프와 **다른 곳**에 보관합니다.

## 8. 지금 self-host 를 막는 빈틈과 작은 고침 제안

상태: G1·G2·G4·G5·G10 은 고쳤습니다. 나머지는 제안입니다.

| # | 빈틈 | 영향 | 작은 고침 |
|---|---|---|---|
| G1 | 공개 서버 이미지 없음. ~~저장소의 `deploy/Dockerfile` 빌드 실패~~ | 직접 빌드해야 함 | **고침**: `deploy/Dockerfile` 이 키트처럼 `COPY . .` + 루트 `.dockerignore`(cmd/nexus 가 쓰는 패키지만 허용)로 빌드됨(`docker build -f deploy/Dockerfile .` 확인). 남은 것: 태그마다 멀티아치 이미지를 GHCR 에 digest 와 함께 게시 |
| G2 | ~~owner 정책이 고정 주소에 묶임~~ | — | **고침**: 사용자 추가 승인·월간 토큰 증액·`nexus approvals` 가 모두 `NEXUS_OWNER_EMAIL` 을 따름. 빈 값·잘못된 값이면 owner 기능 없음. 운영 서버는 같은 주소를 설정하므로 동작이 같음 |
| G3 | owner 외 가입이 메일 필수, 메일은 Resend 만(`https://api.resend.com/emails` 고정). 가입 설정은 메일 키가 없으면 켜지지 않음 | owner 는 G4 로 해결, 다른 사람은 메일 제공자 필요. 메일 없이 시작하려면 자리표시 키 | `Mailer` 인터페이스에 SMTP 구현 추가(`SMTP_URL`), 메일 키 없이도 가입 설정 허용(코드 전용) |
| G4 | ~~메일 없이 owner 를 만드는 공식 경로 없음~~ | — | **고침**: `NEXUS_OWNER_CODE=1` 일 때 `enrol-owner` 가 설정된 owner 용 1회·15분 코드(owner 당 하나)를 운영자 터미널에만 출력 → `newtype auth enrol --code`(숨김 프롬프트/stdin). 기존 가입 표 재사용(스키마 변경 없음), 토큰은 지금처럼 클라이언트가 claim (§4-A) |
| G5 | ~~클라이언트가 `https://` origin 만 받음~~ (macOS 는 여전히 `SSL_CERT_FILE` 을 따르지 않음) | 로컬 시험은 이제 루프백 http 로 가능 | **고침**: `http://127.0.0.1`·`http://localhost`·`http://[::1]`(아무 포트)만 개발용으로 허용, 그 밖은 https 만 |
| G6 | 실제 클라이언트 IP 를 Cloudflare 가정(`CF-Connecting-IP`, 그것도 루프백 peer 일 때만)으로만 얻음 | Caddy·nginx 뒤에서는 모든 요청이 프록시 IP 하나 → IP 별 한도가 사람 전체에 걸림 | `NEXUS_TRUSTED_PROXIES=172.16.0.0/12` 같은 설정에서만 `X-Forwarded-For` 의 마지막 hop 신뢰 |
| G7 | 원격 MCP 브라우저 Origin 허용 목록이 claude.ai/claude.com 고정 | 다른 웹 클라이언트는 브라우저에서 못 붙음(서버 간 클라이언트는 무관) | `NEXUS_MCP_ORIGINS` 설정 |
| G8 | 루프백이 아닌 DB 는 `verify-full` + 포트 5432 강제, 같은 호스트 DB 는 `NEXUS_ALLOW_LOCAL_DB=1`(이름이 "개발용"처럼 보임)로만 | 키트는 네임스페이스 공유로 해결했지만 이름이 오해를 부름 | 이름을 `NEXUS_DB_LOOPBACK=1` 로(옛 이름은 별칭) |
| G9 | 이미지에 healthcheck 도구 없음(distroless) | compose 의 nexus healthcheck 불가 | `nexus health` 하위 명령(127.0.0.1:PORT/v1/health 확인)을 추가하면 `healthcheck: ["CMD","/nexus","health"]` |
| G10 | ~~공개 저장소 없음~~ | — | **고침**: `https://github.com/newtype-ai-com/nexus`(Apache-2.0) |

## 9. 로컬 시험 (이 문서의 "확인됨"을 다시 재현)

Docker 만 있으면 됩니다. 아무것도 외부로 나가지 않고, 포트는 127.0.0.1 에만 엽니다. 메일은 `api.resend.com` 으로 위장한 mail sink 가 받아 로그에 찍고, 클라이언트는 Linux 컨테이너에서 돕니다(Go 가 Linux 에서는 `SSL_CERT_FILE` 을 따르므로 호스트 신뢰 저장소를 건드리지 않음).

```sh
cd deploy/selfhost
export COMPOSE_FILE=compose.yaml:dev/compose.dev.yaml
./dev/gen-dev-certs.sh
# 클라이언트: 서명된 배포본(https://lic.newtype-ai.com/llm.txt)의 Linux 바이너리를 dev/bin/newtype 에 둡니다
cp .env.example .env    # 값: BASE_URL=https://nexus.localtest (dev overlay 가 BASE_URL·NEXUS_MCP_ISSUER·SEAL_ISSUER 를
                        #   이 값으로 고정하고, mail sink 는 .env 의 BASE_URL 이 다르면 시작하지 않음),
                        # owner=ENROL_ALLOW=owner@selfhost.test, RESEND_API_KEY=아무 문자열, 비밀값은 openssl
docker compose build nexus && docker compose up -d postgres
docker compose run --rm nexus migrate
docker compose up -d nexus caddy
docker compose run --rm client auth enrol --gate-url https://nexus.localtest --email owner@selfhost.test \
  --credential-dir /home/client/.newtype/credentials &
docker compose logs mailsink            # {"to": [...], "subject": "Newtype 설치·로그인 승인", "links": ["https://nexus.localtest/enrol/verify?t=vfy_…"]}
curl --cacert dev/certs/ca.crt --connect-to nexus.localtest:443:127.0.0.1:8443 -X POST '<그 링크>'
docker compose run --rm -T client nexus peers --as alice
docker compose --profile tls --profile client down -v   # 끝나면 볼륨까지 삭제
```

(macOS zsh 는 변수 안의 공백으로 명령을 나누지 않으므로 `COMPOSE_FILE` 환경 변수를 쓰세요.)

`gen-dev-certs.sh` 의 일회용 CA 는 `nexus.localtest`·`api.resend.com` 두 이름만 서명할 수 있고(nameConstraints, pathlen 0), 서명 직후 CA 키를 지웁니다. 키는 0600, 각 컨테이너는 자기 인증서·키 파일만 읽기 전용으로 마운트합니다. TLS 없이 시험하려면 Mac 에서 바로 `newtype auth enrol --gate-url http://127.0.0.1:8080 --code` 를 써도 됩니다(루프백 http 허용, G5).

## 10. 문제 해결

| 증상 | 원인·조치 |
|---|---|
| nexus 가 `schema mismatch; run explicit migration` 로 재시작 반복 | 첫 시작 또는 업그레이드 뒤 migrate 를 안 함 → `docker compose stop nexus && docker compose run --rm nexus migrate && docker compose up -d nexus` |
| `nexus: database connection failed (…)` | `POSTGRES_PASSWORD` 가 hex 가 아님(URL 깨짐) 또는 postgres 가 아직 healthy 아님. 볼륨이 이미 있으면 비밀번호를 바꿔도 DB 에는 옛 값이 남음 |
| `DATABASE_URL requires sslmode=verify-full without fallback` | 루프백이 아닌 DB 인데 TLS 검증이 없음. 같은 호스트면 키트의 네임스페이스 공유 방식, 외부 DB 면 `sslmode=verify-full&sslrootcert=…` |
| `nexus: invalid enrolment configuration` | `BASE_URL` 이 https origin 이 아님, `ADMIN_TOKEN` 이 32자 미만, `ENROL_ALLOW` 형식 오류(도메인은 `@` 없이 `example.com`), owner 가 있는데 `ENROL_ALLOW` ≠ owner |
| `enrolment requires BASE_URL, ENROL_ALLOW, RESEND_API_KEY and MAIL_FROM` | 넷 중 하나라도 있으면 넷 다 필요 |
| 클라이언트 `gate: mail_unavailable` | Resend 거절(키·발신 도메인). Resend 대시보드의 로그 확인 |
| 클라이언트 `gate: enrol_not_allowed` | 그 주소가 `ENROL_ALLOW`(owner 모드에서는 owner)와 다름 |
| `newtype auth enrol --code` 가 `gate: not_found` | 코드가 이미 쓰였거나, 15분이 지났거나, 더 새 코드로 바뀌었거나, 서버의 `NEXUS_OWNER_CODE` 가 꺼져 있거나 `NEXUS_OWNER_EMAIL` 이 다른 주소. 운영자가 `docker compose run --rm enrol-owner` 를 다시 실행 |
| `enrol-owner is off; set NEXUS_OWNER_CODE=1` | `.env` 에 `NEXUS_OWNER_CODE=1` 을 넣고 `docker compose up -d nexus` 로 다시 시작 |
| nexus 가 `/data` 에 못 씀(모델 호출 예산 파일 등) | 이 키트 이미지는 빈 `/data` 를 uid 65532 소유로 만들어, 새 `nexusdata` 볼륨이 그 소유를 이어받습니다. 이전 이미지로 이미 만든 볼륨은 root 소유로 남으니 `docker compose down` 뒤 `docker volume rm <프로젝트>_nexusdata`(그 안의 파일이 필요 없을 때) 또는 `docker run --rm -v <프로젝트>_nexusdata:/d postgres:17 chown 65532:65532 /d` |
| `gate: explicit HTTPS origin required` | `--gate-url` 이 https 가 아니고 루프백(`127.0.0.1`·`localhost`·`[::1]`) http 도 아님 |
| `--gate-url is for enrolment only; credentials for another Gate are already saved` | 이미 다른 서버 자격이 있음 → 다른 `HOME` 또는 `--credential-dir` |
| `POST /mcp` 가 401 | 토큰 없는 요청이면 정상. Claude Code 는 이 응답으로 OAuth 를 시작함 |
| `/llm.txt` 404 | `NEXUS_RELEASES_DIR` 이 비어 있음(정상) |
| 원격 MCP 동의 페이지에서 계속 대기 | 사람이 `newtype nmcp authorize CODE` 를 해야 넘어감(메일 동의는 승인 서버 `nexus approvals` 가 있을 때만) |

---

## English summary

**Run your own Nexus.** Kit: `deploy/selfhost/` (PostgreSQL 17 pinned by digest, nexus built from this repo into a distroless image, optional Caddy TLS, `.env.example` with every variable, and a local-trial overlay in `dev/`).

Verified on 2026-10-05 (Docker Desktop 29.2, arm64), all on loopback with a throwaway CA and a mail sink standing in for Resend:

1. `docker compose run --rm nexus migrate` → `Nexus and Gate migrations complete` (serve before migrate refuses with `schema mismatch; run explicit migration`; upgrades never migrate by themselves).
2. `docker compose up -d nexus` → `GET /v1/health` 200 `{"enrolment_schema":4,"gate_schema":1,"nexus_schema":9,"ok":true}`.
3. Owner without mail (`NEXUS_OWNER_CODE=1`: off by default in the server; the self-host kit turns it on; set 0 after the owner has enrolled): `docker compose run --rm enrol-owner` prints a one-time code (15 min, single use, one active per owner, configured owner only; Nexus never writes it and the service's Docker logging is off) → on the owner's computer `newtype auth enrol --gate-url https://<domain> --code` and paste the code at the hidden prompt (or one line on stdin) → `Gate: valid`. Redemption leaves an audit line with the enrolment id and, with mail configured, notifies the owner. Or the normal mail enrolment with `NEXUS_OWNER_EMAIL` = `ENROL_ALLOW`: `newtype auth enrol --gate-url https://<domain> --email <owner>` → approve the mailed link. Mail-free start still needs placeholder `RESEND_API_KEY`/`MAIL_FROM` values (G3).
4. Two sessions exchanged a message (`newtype nexus send --as alice --to bob …` / `newtype nexus inbox --as bob`).
5. `newtype nmcp serve --name claude-code` answered `initialize`, `tools/list` (9 tools), `nexus_peers`, `send_message`.
6. Remote MCP with `NEXUS_MCP_ISSUER`: full OAuth (register → authorize → `newtype nmcp authorize CODE` → token → `POST /mcp` initialize + `tools/call`). Unauthenticated `POST /mcp` returns 401 with `WWW-Authenticate` — expected.
7. Multi-user without an owner (`ENROL_ALLOW=a@x.com,team.example`) and `pg_dump`/`pg_restore` backups.

Not verified: real Resend delivery, public ACME certificates, Cloudflare tunnel, the TUI (needs a model; relay off), the model relay, Claude Code itself against a self-hosted origin.

Fixed: `deploy/Dockerfile` builds again (G1); every owner feature (user admission, quota approval, `nexus approvals`, default-model allowlist) follows `NEXUS_OWNER_EMAIL`, and an empty owner enables none (G2); opt-in mail-free owner bootstrap `enrol-owner` + `newtype auth enrol --code` (G4; the hosted server does not enable it); the client accepts loopback `http://127.0.0.1|localhost|[::1]` origins for development (G5).
Remaining gaps (details in §8): no published image (G1); other people's enrolment needs Resend mail and enrolment settings still require mail values (G3); client IPs assume Cloudflare (G6); fixed MCP browser origins (G7).
