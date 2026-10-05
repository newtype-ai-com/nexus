# NMCP 5단계 — Nexus 가 여는 원격 MCP 엔드포인트 (설계, 2026-10-04)

상태: **구현됨** — §9.

표기: 아래 `https://nexus.example.com` 은 `NEXUS_MCP_ISSUER` 로 설정한 Nexus 의 공개 origin 이다(호스팅 서비스에서는 `https://lic.newtype-ai.com`).

목표: 설치 없이 MCP 클라이언트(claude.ai 커넥터, Claude Code `--transport http`, 다른 호스트)가 `https://nexus.example.com/mcp` 에 붙어 로컬 `newtype nmcp serve` 와 **같은 계약**(`nexusops.Defs`, 같은 의미·같은 영수증 규칙)을 쓴다. 이 문서는 설계이며 구현은 이 문서를 따른다.

## 0. 원칙

1. **토큰은 "붙어도 되는가", 위임은 "해도 되는가".** OAuth 액세스 토큰은 사람이 이 클라이언트를 이 계정에 연결하도록 허락했다는 것만 증명한다. 각 도구 호출의 허용·거절은 언제나 그 연결의 Nexus 세션 위임(`delegation_info`, 정책 auto/ask/deny, 한도, 만료)이 정한다. 토큰 scope 로 위임을 넓힐 수 없다.
2. **같은 계약, 같은 코드.** 원격 엔드포인트는 `internal/nmcp.Server` 를 그대로 쓰고 전송만 바꾼다(stdio 줄 ↔ Streamable HTTP). 도구 정의·지시문·annotations·Tasks·elicitation·구독·영수증 규칙이 한 곳에 있다.
3. **토큰 통과 금지.** `/mcp` 용 토큰은 `/mcp` 에서만 받는다(audience = `https://nexus.example.com/mcp`). `/v1/*` 는 그 토큰을 받지 않고, 서버도 그 토큰을 어디로도 넘기지 않는다. 다른 서버용 토큰(다른 audience)은 거절한다.
4. **사람만 권한을 넓힌다.** 원격 클라이언트의 승인 요청은 elicitation → (답이 없으면) 메일 승인으로 사람에게 간다. 어느 경로의 승인도 Nexus 위임을 넓히지 않는다(로컬과 같음).
5. **원장에 남는다.** 연결·토큰 발급·철회·도구 호출·승인은 계정 원장(또는 연결 세션 원장)에 남고, 각 기록은 누가 누구를 대신했는지(행위자 사슬, §6)를 담는다.

## 1. 전송 — Streamable HTTP (MCP 2025-06-18 / 2025-11-25)

경로: `POST|GET|DELETE /mcp` (`nexus serve`). 지원 버전은 로컬과 같은 목록.

- **POST /mcp**: 본문은 JSON-RPC 메시지 하나(배치 없음, 로컬과 같음). `Accept` 에 `application/json` 과 `text/event-stream` 이 모두 있어야 한다.
  - 요청이면: 그 요청의 응답이 나올 때까지 SSE(`text/event-stream`)로 답한다. 그 사이 서버가 보내는 요청·알림(예: `elicitation/create`, `notifications/progress`)도 같은 스트림에 실린다. 응답을 쓰면 스트림을 닫는다. 즉시 끝나는 요청(`initialize`, `tools/list`, `ping`)은 `application/json` 한 번으로 답할 수 있다.
  - 알림·응답(클라이언트가 우리 `elicitation/create` 에 답하는 것)이면 `202 Accepted`, 본문 없음.
- **GET /mcp**: 서버→클라이언트 독립 스트림(SSE). 요청과 무관한 알림(`notifications/resources/updated`)과, 진행 중인 POST 스트림이 없을 때의 서버 요청이 여기에 실린다. 세션당 하나. 30초마다 `: heartbeat`.
- **DELETE /mcp**: 세션 끝. 진행 중 호출 취소(응답·읽음 없음, 로컬과 같음), 감시자 종료.
- **세션**: `initialize` 응답 헤더 `Mcp-Session-Id`(추측 불가 256비트, 서버 메모리의 연결 표 키). 이후 모든 요청은 이 헤더와 `MCP-Protocol-Version` 을 보내야 한다. 모르는 세션은 `404`(클라이언트가 다시 initialize). 세션은 **토큰의 (계정, client_id)에 묶인다**: 다른 토큰으로 같은 세션 ID 를 쓰면 `404`.
- **재개**: SSE 이벤트에 `id` 를 붙이고 `Last-Event-ID` 로 다시 연 GET 스트림에 놓친 알림을 다시 보낸다(세션당 최근 256개, 메모리). POST 스트림은 재개하지 않는다(끊기면 그 호출은 취소로 본다: 응답·영수증 없음, 결과를 모르는 쓰기 도구는 로컬과 같은 `cancelled` 의미).
- **보안 헤더**: `Origin` 이 있으면 허용 목록(`https://claude.ai`, `https://nexus.example.com`, 설정값)만. 없으면(서버 간 클라이언트) 통과. 요청 본문 4 MiB, 세션 수 계정당 16, 전체 1024, 유휴 30분 뒤 정리.
- **구현 방식(어댑터)**: 연결마다 `nmcp.Server` 하나를 메모리 파이프 위에서 돌린다. POST 본문을 그 서버 입력에 한 줄로 쓰고, 출력 줄을 읽어 — 그 POST 의 id 와 같은 응답이면 그 POST 스트림에 쓰고 닫고, 진행 중인 POST 가 있으면 서버 요청·알림을 그 스트림에, 없으면 GET 스트림(또는 재개 버퍼)에 넣는다. 서버 쪽 코드는 stdio 와 한 글자도 다르지 않다.

## 2. 인증 — OAuth 2.1 보호 자원 서버 (MCP 권한 명세)

Nexus 서버는 **보호 자원 서버**이자, 지금 단계에서는 같은 프로세스 안의 **권한 서버**다(나중에 분리 가능하도록 경로·저장소를 나눈다).

### 2.1 발견

- `401` 응답: `WWW-Authenticate: Bearer resource_metadata="https://nexus.example.com/.well-known/oauth-protected-resource/mcp", scope="nexus:connect"`. 토큰은 있으나 부족하면 `403` + `error="insufficient_scope"`.
- `GET /.well-known/oauth-protected-resource/mcp` (RFC 9728, 경로 붙은 형태가 우선, 뿌리 `/.well-known/oauth-protected-resource` 도 같은 문서):
  `{"resource":"https://nexus.example.com/mcp","authorization_servers":["https://nexus.example.com"],"scopes_supported":["nexus:connect"],"bearer_methods_supported":["header"],"resource_name":"Newtype Nexus"}`
- `GET /.well-known/oauth-authorization-server` (RFC 8414): `issuer`, `authorization_endpoint` `/oauth/authorize`, `token_endpoint` `/oauth/token`, `registration_endpoint` `/oauth/register`, `revocation_endpoint` `/oauth/revoke`, `response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token"]`, `code_challenge_methods_supported:["S256"]`, `token_endpoint_auth_methods_supported:["none"]`(공개 클라이언트, PKCE 필수), `client_id_metadata_document_supported:false`(1차; §2.6).

### 2.2 클라이언트 등록

- **동적 등록**(RFC 7591) `POST /oauth/register`: `client_name`, `redirect_uris`(https, 또는 `http://127.0.0.1:*`/`http://localhost:*` 루프백만; 정확히 일치 비교), `grant_types`, `token_endpoint_auth_method:"none"`. 결과 `client_id`(`mcl_…`). 비밀은 발급하지 않는다. 등록만으로는 아무 권한도 없다(사람의 동의 전엔 토큰이 없다). 남용 대비: IP·전체 등록 속도 제한, 90일 미사용 등록 정리.
- 등록 기록은 계정에 속하지 않는다(누구의 것도 아닌 공개 클라이언트). 동의가 계정과 client_id 를 잇는다.

### 2.3 권한 부여 — 사람이 클라이언트를 허락하는 법

`GET /oauth/authorize?response_type=code&client_id&redirect_uri&code_challenge&code_challenge_method=S256&state&scope=nexus:connect&resource=https://nexus.example.com/mcp`

- `resource`(RFC 8707)는 필수이고 정확히 `https://nexus.example.com/mcp` 여야 한다. 아니면 `invalid_target`. `redirect_uri` 는 등록값과 정확히 일치해야 하고, 틀리면 리디렉트하지 않고 오류 페이지.
- **사람 확인(1차: 기존 로그인에 맞춤)**: 동의 페이지는 "클라이언트 *client_name* (리디렉트 호스트 표시)이 Nexus 계정에 연결하려 합니다 · 연결하면 이 클라이언트용 세션이 만들어지고, 그 세션은 도구 전용 위임(모델 없음, `session:delegate` 한 단계)만 받습니다" 를 보이고, 다음 둘 중 하나로 확인한다.
  1. **이메일 확인**: 동의 페이지의 "확인 메일 보내기" → Nexus 가 승인 서버에 `mcp_connect` 변경 요청(관리 클라이언트) → 승인 서버가 **owner 주소**(`NEXUS_OWNER_EMAIL`)로 1회용 링크를 보냄 → 사람이 링크에서 승인 → 동의 페이지 폴링이 승인을 보고 `Consume`(한 번) → 그 주소의 계정(`gate_credentials`/`gate_accounts` 에서 정확히 하나)으로 동의를 만들고 `redirect_uri?code&state&iss` 로 보낸다. 승인 서버가 owner 에게만 메일을 보내므로 메일 확인은 owner 계정 전용이다(owner 한정 정책과 같음).
  2. **CLI 확인**: 페이지에 8자리 사용자 코드 → 살아 있는 로그인이 있는 사람이 `newtype nmcp authorize CODE` (기존 기기 흐름 `/v1/device` 와 같은 모양) → 페이지가 진행.
  - 둘 다 **이미 있는 로그인·메일 경로**를 쓴다. 비밀번호 입력 없음.
  - 페이지는 `X-Frame-Options: DENY`, CSP(`script-src 'self'`, `frame-ancestors 'none'`), `no-store`. 페이지를 여는 것만으로는 아무것도 허락되지 않는다. 대기 요청은 15분, 최대 256개(메모리).
  - **나중(패스키)**: 동의 페이지에서 WebAuthn 어서션(계정 루트 패스키)으로 바로 확인. 패스키 도메인이 생기면 1·2 를 대체한다(`docs/03-mandate.md` 의 패스키 설계와 같은 키).
- 코드: `mca_…` 1회용, 60초, PKCE `S256` 검증, client_id·redirect_uri·resource 와 묶임. 두 번 쓰면 그 코드로 발급된 토큰을 모두 철회(RFC 6749 §4.1.2 권고).

### 2.4 토큰

- `POST /oauth/token` `grant_type=authorization_code` (+`code_verifier`, `redirect_uri`, `client_id`, `resource`) → `{"access_token":"ntm_…","token_type":"Bearer","expires_in":3600,"refresh_token":"ntr_…","scope":"nexus:connect"}`.
- **불투명 토큰**, 서버는 SHA-256 검증값만 저장(gate 자격 증명과 같은 방식). 기록: 검증값, 종류(access/refresh), client_id, 계정, 이메일, **audience = `https://nexus.example.com/mcp`**, scope, 동의 ID, 만료, 철회.
- 액세스 1시간, 리프레시 30일 회전(쓸 때마다 새 리프레시). 회전된 옛 리프레시를 다시 쓰면 도난으로 보고 **그 동의 자체를 철회**한다(토큰 전부 무효, 사람이 다시 허락해야 함).
- 철회: `POST /oauth/revoke`(RFC 7009), 사람 쪽 `newtype nmcp clients` / `newtype nmcp revoke CLIENT`(동의 목록·철회), 그리고 계정 로그인 철회 시 함께 철회.
- **검사(`/mcp` 매 요청)**: Bearer 하나, `ntm_` 접두어, 검증값 조회, 종류 access, 미철회, 미만료, **audience 정확히 일치**, scope 에 `nexus:connect`, 동의 미철회. 하나라도 틀리면 `401`(+`WWW-Authenticate`). 쿼리 문자열 토큰은 받지 않는다.
- `/v1/*` 의 인증(`executorOrGate` → gate)은 `ntm_`/`ntr_` 를 **거절**한다(접두어로 바로 401). 반대로 `/mcp` 는 licence·login·agent·executor 토큰을 거절한다.
- 저장소: 새 표 `mcp_oauth_clients`, `mcp_oauth_consents`, `mcp_oauth_codes`, `mcp_oauth_tokens`(Nexus 의 Postgres, 기존 `gate_meta` 버전 이전 방식). `gate_credentials.kind` CHECK 를 바꾸지 않는다(로그인 자격 증명과 섞지 않기 위해). 테스트용 메모리 구현.

### 2.5 연결 → 세션 → 위임

- 첫 `initialize` 때 (계정, client_id, `clientInfo.name`) 으로 **연결 세션**을 찾거나 만든다: 제목 `mcp:<client_name>`(사람이 `nexus peers` 에서 알아보게), runner `local` 과 구별되는 새 runner **`remote`**(Nexus 서버가 대신 돌리는 MCP 연결; 컨테이너도 사람 터미널도 아님). 동의 하나에 세션 하나(같은 클라이언트의 여러 MCP 세션은 같은 Nexus 세션을 공유하고, 받은편지함도 공유).
- 루트 위임: 로컬 `nmcpRoot` 와 같다 — 범위 `session:delegate` 하나, 모델 토큰 0, `max_depth` 1, 8시간, 사람 = 동의한 계정 사람. 만료되면 다음 `initialize` 에서 다시 발급(동의가 살아 있는 동안).
- 도구 호출은 이 세션 주체(`SessionPrincipal(account, session)`)로 실행된다. **판정은 서버의 위임 검사**(로컬과 같은 `nexus.Service` 경로)이며 토큰은 관여하지 않는다.
- **프로세스 안 호출(토큰 없이)**: `nexusops.Seat` 는 HTTP 클라이언트를 쓰므로, 서버 안에서는 `nexustransport.Client.WithTransport` 에 **프로세스 안 RoundTripper** 를 준다. 이 RoundTripper 는 요청 context 에 검증된 주체를 넣어 서버의 `http.Handler` 를 직접 부른다. `executorOrGate` 앞단이 context 의 주체를 먼저 보고(네트워크 요청은 Go context 값을 실을 수 없다), 없을 때만 헤더 인증으로 간다. 그래서 `/v1/*` 의 인가·한도·원장 코드는 그대로 지나가고, OAuth 토큰은 `/v1/*` 로 흘러가지 않는다(원칙 3). `Reauthenticate`(스트림)도 같은 context 주체를 보고, 동의·토큰이 철회되면 연결 표에서 그 세션을 끊어 스트림을 끝낸다.
- 세션 주체가 `remote` runner 를 가질 수 있게 gate 의 세션 검사(`Local` 만 허용)는 건드리지 않는다: 프로세스 안 주체는 헤더 인증을 거치지 않으므로 필요 없다. 대신 `remote` 세션은 헤더로는 절대 인증할 수 없다(licence+login+`X-Newtype-Session` 으로 `remote` 세션을 쓰면 401 — 지금 코드가 이미 `Local` 만 허용).

## 3. 같은 의미 (로컬과 같음)

- 지시문(KO+EN), annotations, `nexus_inbox` 대기(로컬과 같은 최대 600초; 긴 호출은 POST SSE 를 바로 열고 30초마다 `: heartbeat` 를 보내 프록시 유휴 한도(예: 100초)에 끊기지 않는다), Tasks(연결 세션 메모리 동안), elicitation(클라이언트가 선언하면), `nexus://inbox`·`nexus://tasks/{id}` 구독과 receipt-free 알림 — 모두 `nmcp.Server` 그대로.
- 읽음 = 결과가 클라이언트에게 쓰인 뒤. 원격에서는 "응답 SSE 이벤트를 쓰고 flush 가 성공한 뒤"다. 쓰기 실패·연결 끊김이면 읽음 없음.
- `claude/channel` 은 원격에서 선언하지 않는다(Claude Code channel 은 stdio 하위 프로세스 전용).
- `tool.call` 기록은 연결 세션 원장에, §6 의 행위자 사슬을 붙여 남긴다.

## 4. 승인 — elicitation, 그리고 아무도 답하지 않을 때 메일

`request_approval` 경로(결정은 언제나 하나):

1. 서버가 이미 허용(auto) → 허용.
2. 이 연결에서 사람이 "이 세션 동안" 승인한 행동 → 승인.
3. 클라이언트가 elicitation 을 선언 → `elicitation/create`, **최대 2분**. 사람이 답하면 그 결과(once/session/deny), 원장 `tool.approval decided_by person:mcp-elicitation`.
4. elicitation 이 없거나 2분 안에 답이 없거나 `cancel` → **메일 승인**(서버 쪽, Nexus 서버가 가진 승인 서버 관리 토큰):
   - Nexus 서버가 `gate.ChangeAdminClient.Begin` 과 같은 관리 경로로 승인 서버에 새 종류의 요청 `mcp_approval` 을 만든다(`POST /v1/changes`, 내용: 계정, 연결 세션, client_name, 행동, 이유 요약 2000자, 만료 15분). 승인 서버가 계정 이메일(지금은 owner 만)로 링크를 보낸다. 링크 페이지는 기존 승인 페이지(승인/거절)를 그대로 쓴다. 그래서 **메일 승인은 언제나 "한 번만"** 이고, "이 세션 동안" 은 elicitation 으로만 고를 수 있다.
   - 기다림: Tasks 로 부른 `request_approval` 은 작업 핸들을 바로 돌려주고 메일 결과까지 기다린다(`tasks/result`). Tasks 가 없으면 `request_approval` 이 `wait_seconds`(기본 0, 최대 300) 동안 기다렸다가 결정이 없으면 `{"status":"pending","via":"mail","approval_id":…}` 를 돌려준다. 같은 `action`·`reason` 으로 다시 부르면 새 메일 없이 같은 요청의 상태를 본다(요청 키 = 연결 세션 + 행동 + 이유).
   - 결과는 `Consume` 으로 한 번만 가져와 원장 `tool.approval decided_by person:mail` 로 남기고, "이 세션 동안" 이면 그 연결의 프로세스 승인 표에 넣는다.
   - 관리 토큰은 Nexus 서버의 비공개 환경 파일에만 있고, 도구 결과·로그·원장 어디에도 나오지 않는다. 승인 서버의 `/v1/changes` 는 공개 프록시에서 열지 않는다(외부 접근 불가).
5. elicitation 거절(`decline`/`deny`) → 거절, 메일로 넘어가지 않는다(사람이 이미 답했다).

로컬 `newtype nmcp serve` 는 관리 토큰이 없으므로 지금처럼 4 대신 운영자 자리 메시지를 쓴다. 나중에 로컬에서도 메일을 원하면 Nexus 의 새 경로(`POST /v1/approvals/mail`, 세션 주체가 호출, Nexus 가 대신 승인 서버에 요청)를 쓰면 되고, 그때도 관리 토큰은 Nexus 밖으로 나가지 않는다.

## 5. 공개 프록시와 SSE

- `/mcp`, `/.well-known/oauth-*`, `/oauth/*` 는 `/v1/*` 와 같은 Nexus 서버로 보낸다. 승인 서버 관리 경로(`/v1/changes`)와 `/metrics` 는 공개하지 않는다.
- 프록시는 스트림을 버퍼링하지 않아야 한다(selfhost 의 Caddy 는 `flush_interval -1`). 유휴 한도가 있는 프록시는 30초 heartbeat 로 충분하다(예: 100초 한도).
- 배포 뒤 확인:
  1. `curl -N -H 'Accept: text/event-stream' …/v1/sessions/<id>/stream`(기존 스트림)으로 `: connected` 와 30초 `: heartbeat` 가 지연 없이 오는지(버퍼링 없음), 4분 수명 끝에 정상 종료되는지.
  2. `/mcp` POST 로 `nexus_inbox wait_seconds:120` 을 SSE 로 받는 동안 다른 세션이 메시지를 보내면 즉시 응답 이벤트가 오는지.
  3. GET `/mcp` 스트림을 10분 열어 두고 heartbeat 로 끊기지 않는지.
  - 서버 쪽: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`, 압축 없음, 매 이벤트 flush(기존 `stream` 핸들러와 같음).

## 6. 행위자 사슬 — RFC 8693 `act` 검토

RFC 8693(토큰 교환)의 `act` 클레임은 "주체(sub)를 대신해 행위자(act.sub)가 행동한다" 를 중첩으로 적는다(가장 바깥이 지금 행위자, 안쪽으로 갈수록 이전 행위자).

- **토큰 교환은 하지 않는다.** Nexus 는 MCP 토큰을 다른 토큰으로 바꿔 다른 서버에 보내지 않는다(원칙 3). Nexus 안의 "대신함" 은 이미 **위임 인증서 사슬**(`nexus/certificate.go`, `Chain []CertLink`: 위임자 → 위임받은 세션, 범위는 아래로만 좁아짐)이 증명한다.
- 대신 **기록 형식만 RFC 8693 모양**으로 맞춘다. 원격 연결의 원장 기록(`tool.call`, `tool.approval`, `message.sent` 의 행위자 메타)에 다음을 붙인다.

```json
"act_chain": {
  "sub": "person:<account>",
  "act": {"sub": "mcp_client:<client_id>", "client_name": "Claude", "consent": "<consent id>",
          "act": {"sub": "session:<slv_…>", "delegation": "<del_…>"}}
}
```

  읽는 법: 사람(sub)이 MCP 클라이언트에게 연결을 허락했고(동의), 그 클라이언트가 연결 세션으로서(위임) 이 행동을 했다. 하위 세션에 `delegate_task` 로 맡긴 일은 받는 세션의 기록에서 인증서 사슬이 한 단계 더 붙는다.
- 검토 결과(요약):
  - 순서: RFC 8693 은 가장 바깥이 **현재** 행위자다. 위 JSON 은 사람에서 시작하는 "출처 순서"이므로, 필드 이름을 `act_chain`(우리 형식)으로 두고 `act` 클레임과 혼동하지 않게 문서화한다. 외부로 내보낼 일이 생기면 그때 뒤집어 표준 `act` 로 만든다.
  - `may_act`: 동의 기록이 `may_act` 에 해당한다(이 사람이 이 client_id 의 행위를 허락). 별도 클레임 없이 동의 ID 로 가리킨다.
  - 행위자 사슬은 **설명**이지 권한이 아니다: 판정은 언제나 연결 세션의 위임이 한다. 사슬의 어느 고리(동의 철회, 토큰 철회, 위임 만료)가 끊기면 그 뒤 호출은 거절된다.
  - 클라이언트가 보낸 `clientInfo`·`client_name` 은 자기 신고이므로 표시용이다. 신원은 client_id(등록) + 동의(사람)다.

## 7. 구현 단위와 시험 (실제 파일)

| 단위 | 위치 | 시험 |
|---|---|---|
| Streamable HTTP 어댑터(같은 `nmcp.Server`) | `internal/nmcp/httpserver.go` | `httpserver_test.go`: initialize→`Mcp-Session-Id`(JSON), tools/call SSE, 알림 202, 다른 토큰의 세션 404, Origin 403, 401+`resource_metadata`, SSE 를 쓴 뒤에만 읽음, 끊긴 POST 는 응답·영수증 없음, elicitation 이 POST 스트림으로·답은 POST 202, GET 스트림 알림과 `Last-Event-ID` 재개, DELETE |
| 적합성(엔진 = stdio = HTTP) | `internal/nmcp/conformance_test.go` | 기존 세 시나리오를 세 경로로 |
| OAuth 서버·자원 검사·사람 경로 | `internal/mcpauth/server.go` | `endpoint_test.go`: 발견 문서, 401 헤더, resource 필수, PKCE, 코드 재사용 → 동의 철회, 다른 audience·refresh·licence 토큰 401, `/v1` 이 `ntm_` 거절, 리프레시 회전·재사용 → 동의 철회, 사람 철회 → 열린 연결도 끝 |
| 저장소 | `internal/mcpauth/store.go`(메모리), `postgres.go`(`mcp_oauth_*`, `gate_meta` 키 `mcp_oauth`=1) | 메모리 저장소로 위 시험 |
| 연결 세션·위임·행위자 사슬 | `internal/mcpauth/connect.go` | CLI 코드 동의 → `remote` 세션 `mcp:Claude`, 위임 밖 `delegate_task` 는 `refused`, `tool.call` 에 `act_chain`, 같은 동의는 같은 세션 |
| 메일 동의·메일 승인 대체 경로 | `server.go`(`mcp_connect`), `connect.go` `MailApprovals`(`mcp_approval`), `internal/nexusops/contract.go` `mailApproval` | 메일 동의, `request_approval`: 첫 호출 메일 한 번, 다시 불러도 같은 요청, 승인 뒤 `once`·Consume 한 번 |
| `remote` runner | `nexus/model.go`, `nexus/issuance.go`, `nexus/httpapi/roots.go`·`delegations.go`(공개 API 는 거절) | `internal/nexusserver/inprocess_test.go` |
| 프로세스 안 호출·토큰 분리 | `internal/nexusserver/inprocess.go`(`InProcess`, `PersonAuth`, `/v1` 의 `ntm_`/`ntr_` 거절) | 같은 파일 시험: 프로세스 안 주체로 `/v1` 과 스트림, 네트워크로는 자리표시 토큰·`ntm_`·`ntr_` 401, 공개 API 로 `remote` 루트 거절 |
| 서버 배선 | `cmd/nexus/remote_mcp.go`, `cmd/nexus/main.go`(라우트·정리), `migrate_fd.go`(이전 단계 "mcp oauth"), `internal/nexusserver/config.go`(`NEXUS_MCP_ISSUER`) | 빌드·기존 시험 |
| 승인 서버 종류 | `gate/change_approval.go`(`mcp_connect`, `mcp_approval` 허용) | 기존 시험 |
| 사람 CLI(클라이언트, 이 저장소 밖) | `newtype nmcp authorize CODE`, `clients`, `revoke ID|이름` | 클라이언트 저장소 |

배포: **입력 없는 업그레이드는 마이그레이션을 돌리지 않는다.** ① 새 이미지로 올린다(`NEXUS_MCP_ISSUER` 없이) → ② `nexus migrate` 로 명시적 마이그레이션을 하고, 런타임 역할이 마이그레이션 소유자와 다르면 새 표의 런타임 권한을 준다(마이그레이션은 PUBLIC 만 회수): `mcp_oauth_clients` SELECT/INSERT/UPDATE/DELETE, `consents`·`codes`·`tokens` SELECT/INSERT/UPDATE, `settings` SELECT/UPDATE → ③ 환경에 `NEXUS_MCP_ISSUER=https://nexus.example.com`. 이 값이 없으면 엔드포인트는 꺼져 있다. 이 값이 있는데 표가 없으면 서버가 시작하지 않는다("run explicit migration"). 메일 경로(동의 메일, 승인 메일)는 **승인 서버(`nexus approvals`)도 같은 버전이어야** 동작한다(새 종류 `mcp_connect`·`mcp_approval` 를 승인 서버가 검사함). 그 전에는 메일 버튼이 메일을 보내지 못하고(페이지는 CLI 코드로만 진행), `request_approval` 의 메일 단계는 `approval_unavailable` 이다.

## 8. 결정 (2026-10-04)

1. 동의 확인: 메일 1회용 링크와 CLI 코드 **둘 다**. 나중에 패스키가 둘을 대체.
2. 새 runner **`remote`**(Go enum; 세션은 JSON 문서로 저장되어 저장소 이전은 필요 없음). `local` + 제목 접두어는 쓰지 않는다.
3. 등록은 **동적 등록만**. CIMD 는 SSRF 검토 뒤.
4. 대기: 메일 15분, elicitation 2분.

## 8a. 독립 리뷰 반영 (2026-10-04, FIX-FIRST 12건)

1. 메일 두 흐름의 승인 서버 `ClientID` 를 요청마다 고유하게(동의 = `mcr_` 대기 ID, 승인 = 새 `mcpa_` 난수). 승인 저널은 `Requester+ClientID` 로 영구히 멱등 처리하므로 고정값이면 한 번밖에 안 됐다. 실제 `gate.FileChangeStore` 로 두 번씩 시험.
2. 리프레시 회전을 원자적으로(`UPDATE … WHERE verifier=$1 AND kind='refresh' AND NOT revoked`, 0행 = 재사용 → 동의 철회). 병렬 시험.
3. 기기 코드 피싱: `GET /v1/mcp/authorize?user_code=` 미리보기(클라이언트, 돌아갈 곳, 요청 시각, 요청 IP — 터널 뒤에서는 `CF-Connecting-IP`) → CLI 가 보여 주고 y/N → 그다음 POST. 메일 제목·영향에 코드와 돌아갈 곳.
4. 홍수 제한: 대기 요청 클라이언트당 5·IP 당 10(전체 256), 동의 메일 전체 하루 3통·클라이언트당 하루 1통(24시간 창), 승인 메일 연결 세션당 열린 것 3·15분 만료·전체 20/시간, 등록 IP 당 10/시간(+전체 60/분), 동의 없는 등록은 24시간 뒤 삭제. 승인 서버의 영구 요청 한도(기본 모델 승인과 공유)도 지킨다.
5. 동의는 사람의 자격 증명보다 오래 가지 않는다: `/mcp` 검사·토큰 발급·리프레시 때 그 계정에 살아 있는 licence 와 login 이 있고 owner 정책을 통과하는지 확인(1분 캐시). 동의 절대 수명 90일, 토큰 만료는 그 끝을 넘지 않는다.
6. initialize 마다 루트를 새로 발급하지 않고 살아 있는 remote 루트(1시간 이상 남음)를 재사용. 세션 자리 예약은 잠금 안에서.
7. 다른 세션의 `delegate_task`, 사람의 루트(`to_session_id`), 관찰자 루트가 remote 세션을 겨냥하면 서비스가 거절(연결기의 remote 루트만 허용).
8. 원격 elicitation 답은 `mcp_client:<id>:elicitation` 으로 기록(사람으로 적지 않음).
9. 승인 서버는 owner 에게만 메일을 보내므로 동의의 이메일이 owner 가 아니면 메일 승인을 하지 않고 `approval_unavailable`(owner 한정).
10. 열린 GET/POST 스트림은 하트비트마다 토큰을 다시 확인해 철회·만료 뒤 끝난다.
11. fd 이전의 확인 단계가 `mcp_oauth` 버전도 본다.
12. 동의 페이지 폴링이 승인 서버를 요청당 3초에 한 번만 묻고, 계정 확인을 Consume 앞에서 해 실패해도 다시 시도된다.

시험: `internal/mcpauth/review_fixes_test.go`(클라이언트의 미리보기·y/N 시험은 클라이언트 저장소).

## 8b. 재검토 반영 (2026-10-04)

- **메일 동의 스위치(기본 꺼짐)**: 승인 저장소의 요청 한도는 평생 누적이고 지우지 않는다(기본 모델 승인과 공유). 그래서 메일 동의는 기본 꺼짐이고, 사람이 **명령과 대화로** 켜고 끈다.
  - 서버: `GET/PUT /v1/mcp/settings {"mail_consent": bool}`. 사람 인증만 받고(세션 토큰·`ntm_` 거절), 바꾸는 것은 owner 만(`owner_only` 403). 값은 `mcp_oauth_settings` 한 행(같은 `mcp_oauth` 스키마 1, 아직 배포 전이라 버전은 올리지 않음)에 바꾼 사람·시각과 함께 저장한다. 변경은 원장 `mcp.settings.changed`(from/to/by)로 그 계정의 원격 연결 세션들과 operator 자리에 남는다. 동의 페이지는 켜져 있을 때만 메일 버튼을 보이고, 꺼져 있으면 `authorizeMail` 이 거절한다.
  - CLI: `newtype nmcp mail-consent [on|off]`(인자 없으면 상태). 켤 때는 무엇을 허용하는지(인증 없는 요청자가 owner 메일을 일으킬 수 있음, 하루 예산 안에서) 보여 주고 y/N.
  - TUI: 대화 도구 `nmcp_settings`(get/set)와 `/nmcp mail-consent [on|off]`. 도구는 사람이 직접 친 턴에서만 동작하고(받은편지함·백그라운드 턴 거절), 바꾸기 전 사람 승인(class remote — 어느 모드도 자동 승인하지 않음)을 받는다.
- **승인 메일 하루 예산**: 연결(동의)당 하루 3통, 전체 하루 10통(시간당 한도를 대체).
- **IP 제한은 IPv6 /64 단위**, 대기 요청 전체 상한 64, 2분 동안 폴링되지 않은 대기 요청은 버린다.
- **확인은 미리본 요청에만**: `POST /v1/mcp/authorize` 는 미리보기에서 받은 `request_id` 가 있어야 하고 코드와 맞아야 한다.
- **실행 허가**: 보낸 세션이 remote 이면 실행 허가 발급을 거절한다(원격 연결은 로컬 도구 실행을 지시할 수 없음).
- 남은 일(후속): `mcp_*` 종류만의 별도 승인 저장소 또는 별도 한도. 첫 initialize 두 개가 겹치면 루트가 둘 생길 수 있음(낮음).

## 9. 구현 상태와 남은 것

- 위 §7 의 서버 쪽이 모두 구현되었고 시험이 통과한다(`go test ./internal/mcpauth ./internal/nmcp ./internal/nexusserver ./nexus/...`).
- 배포 뒤 확인: §5 의 SSE 경유 확인 3가지, claude.ai 커넥터 또는 `claude mcp add --transport http nexus https://nexus.example.com/mcp` 로 실제 OAuth 흐름(동의 페이지 → `newtype nmcp authorize CODE`).
- 남은 것: 패스키 동의, CIMD, 연결 세션의 Tasks·재개 버퍼는 프로세스 메모리(재시작하면 클라이언트가 다시 initialize), 대기 동의 요청도 메모리(재시작하면 클라이언트에서 다시 시작).
