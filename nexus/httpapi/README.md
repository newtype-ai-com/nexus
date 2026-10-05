# Nexus 로컬 HTTP / Core 연결 검증

## 수신자 재조정 계약 (P1 큐 연결 선행)

- `GET /v1/inbox`의 각 항목에 `kind`, `sender_kind`를 저장 event/actor에서 채운다. payload의 자기 주장으로 사람 메시지로 승격하지 않는다.
- `delivered_at?`, `read_at?`, `read_turn_id?`는 같은 읽기 트랜잭션에서 검증된 receipt 사건으로 조회한다. 수신자는 자기 Inbox를 다시 읽어 큐 상태를 재조정할 수 있다. 이 메타데이터는 실행 권한이나 모델 원격 수신 증명이 아니다.
- 모델 read 전후 복구용 조회이며 GET 자체는 상태를 변경하지 않는다. `/v1/messages/{id}?to=`의 발신자/사람 접근 경계는 그대로 유지한다.
- `internal/nexusinbox.Client`의 `PollNow`는 SSE 대기 없는 조회, `Delivered/Read`는 명시적인 receipt 호출이다. TUI 표시와 기존 Poll은 이 메서드를 자동 호출하지 않는다. 내구 큐·Core 입력 연결은 후속이다.
- 실제 메모리 HTTP, 메모리/재시도/PG17 적합성 및 PG 복수 pool·새 pool Inbox 재조회로 검증했다.

## 메시지 receipt 서버 계약 (자율 구현 1차)

- `POST /v1/messages/delivered {"event_id":"evt_…"}`, `POST /v1/messages/read {"event_id":"evt_…","turn_id":"req_…"}` → `200 {"ok":true}`. 활성 수신 세션 자신의 실제 Inbox 사건만 허용한다. `turn_id`는 Core 입력 턴 식별자이며 서버가 모델 소비를 직접 관찰하는 증거는 아니다.
- 읽음은 전달을 포함한다. 같은 account 트랜잭션에서 메시지별 멱등 원장 키를 조회·추가하므로 재시도/순서 역전에도 사건이 중복되지 않는다. 최초 read 시각/턴은 바뀌지 않는다. `message.*` 사건과 해당 client ID namespace의 직접 원장 위조는 금지한다.
- `GET /v1/messages/{event_id}?to=slv_…` → `event_id,to,status,sent_at,delivered_at?,read_at?,turn_id?,session_status,last_seen?,reply_id?`. 정확한 원본 발신 세션 또는 같은 계정 사람만 가능하다. 본문/observer 범위/문자열 포함으로 권한을 판정하지 않는다. `last_seen`은 프로세스 내 참고 정보다.
- 답신 링크는 정확한 `(reply sender, original recipient, reply_to, original sender)`가 일치하는 최초 답신만 기록한다. 잘못 연결된 legacy `reply_to` 송신은 유지하지만 상태 응답에 답신으로 승격하지 않는다.
- ID로 지정한 `stopped` 세션에는 살아 있는 위임이 있을 때 보관한다. 이름 검색 제외·발신/실행/receipt 거부는 유지한다. `done`/`suspended`는 계속 거부한다.
- 메모리/강제 재시도/폐기용 PostgreSQL 17 적합성, 두 pool 32동시 read/delivered·pool 재생성 유지, HTTP 권한/상태 회귀 통과. **클라이언트 큐·Core read 호출·TUI 자동 턴은 아직 연결하지 않았다.** 기존 화면 표시/Inbox GET은 상태를 바꾸지 않는다.

## 자기 잔액 조회 기반 (2026-10-02 후임 구현)

- `GET /v1/delegations/{id}/left`는 `{remaining: Limits}`만 반환한다. 봇은 자기 세션의 정확한 위임만, 사람은 같은 계정만 조회한다. 기존 원문 `DelegationInfo`의 봇 거부는 유지한다.
- 숫자는 현재 기본 한도에서 소비·예약을 뺀 조회 스냅숏이며 실행 승인·예약이 아니다. `Raised`/증액/이월/자동 재시도는 아직 구현하지 않았다.
- 역사적 잔액 정책이 확정되기 전에는 만료·철회 계보와 stopped/suspended/done 세션을 보수적으로 거부한다. 조회로 실행 권한을 복원하지 않는다.
- 원문 증서·scope·rules·키는 응답에 없고 잔액 조회 자체는 원장/사용량을 변경하지 않는다(일반 HTTP 인증 touch/presence는 별개).

## 서버 루트 발급 연결 (2026-10-02)

- `POST /v1/requests`, `POST /v1/observers`: 인증된 User만 발급. `RootWire`에 `title`, 선택 `task_id`/`to_session_id`/`runner`, `scope`/`rules`/`approver`/`limits`, 필수 `ttl_seconds`(1~MaxTTL)를 받는다. 기본 runner는 local이다.
- 반환은 `GrantSummary`(task 선택·session·delegation_id·expires_at), 201. worker spawn/agent token 발급/패스키 서명은 아니다. root task_id 재시도는 409이며 자동 재발급하지 않는다.
- `GET /v1/delegations/{id}`는 사람만 원문 정보를 조회. `POST /v1/delegations/{id}/revoke {reason}`는 기존 Service의 사람/유효 하위 위임 취소 규칙을 적용한다.
- 요청 계정·주체 주입, 세션의 root/observer 발급과 원문 조회, 타 계정 조회/취소를 차단한다. 초 단위 TTL overflow/중복 JSON/미지 필드를 거부한다. 실제 HTTP 서버·Postgres 재시작 후 발급 정보 조회를 검증했다.


## 런처 연결 후속 (2026-10-01)

- `POST /v1/delegations`: `DelegateWire`의 명시적 초 단위 TTL(1~MaxTTL)을 검증하고 기존 Service.Delegate로 전달한다. HTTP identity는 인증자에서만 얻는다. 반환은 task/session/delegation ID로 한정하며 자격증명·정책 원문을 내보내지 않는다. worker spawn이나 토큰 발급은 하지 않는다.
- `NewMeteredCoreRunner`는 기존 모델 전용 격리 Core를 유지하며 각 provider 시도의 실제 usage를 누적해 `RunMetered`로 반환한다. 실패·누락·음수·overflow는 -1로 상한을 유지한다. fixed runner는 변경하지 않았다. provider invoice/금액 정산과 상한 강제 중단은 별도다.
- 로컬 런처의 Nexus tools와 licence+login+session 인증 transport, 사람 전용 `nexus-approval` CLI가 연결됐다. 원격 응답은 여전히 상태 전용이며 로컬 파일 도구 Gate나 원격 출력 스트림을 제공하는 API가 아니다.
- 실제 Gate verifier→HTTP→Nexus→격리 Core 테스트에서 로컬 세션 인증, 송신/수신, 자기 승인 거부, 독립 사람 승인, 재실행 방지, 40 토큰 예약→15 토큰 사용→25 환급, scope 확대 거부 및 자격 철회를 확인했다. 사용량 제공 모델은 fixture이며 유료 호출은 아니다.

이 패키지는 **주입형 로컬 통합 어댑터**이며 운영 Gate 서버나 원격 TUI API가 아니다.

## 영구 실행 후속 구현 (2026-10-01, 넥서스 작업)

아래 기존 연결 계약의 프로세스 내 상태 설명은 **`Durable: false`인 기본/legacy 모드**에 해당한다.

- `Config.Durable: true`에서는 요청·정확한 입력 해시 승인·시작·취소·정산을 Nexus 원장에 저장한다. Store가 Postgres면 API/Service를 다시 생성해도 상태가 남는다. `MaxRecords`는 legacy 전용이며 영구 원장 보관/쿼터 정책은 후속 작업이다.
- 실행 시작과 상한 선차감은 한 트랜잭션이다. 동시 요청은 하나만 시작하며 legacy↔durable 전환 시 기존 호출 ID 재사용은 충돌로 막는다.
- 실행 중 서버가 죽으면 `running` 영수증을 자동 재실행하거나 자동 환급하지 않는다. 운영 복구자가 제공자 증거를 확인하고 서버 전용 `SettleExecution`으로 `indeterminate` 등을 기록해야 한다. 자동 복구 스케줄러/lease는 아직 없다.
- `RunMetered`가 있으면 `Actions`는 비용 상한이며 서버가 신뢰하는 runner의 실측 사용량으로 미사용분만 환급한다. 음수/불명확한 사용량과 panic은 상한을 유지한다. 상한 초과는 상한까지 차감하고 `limit.reached`로 남긴다. 이미 종료된 옛 위임 계보에도 환급을 전파한다.
- **기존 `NewCoreRunner`는 여전히 고정 비용 어댑터**다. 실측 runner 계약 테스트가 실제 모델 공급자 정산 연결 완료를 뜻하지 않는다. 생산 환경에서는 provider별 누적 사용량·재시도·초과 방지 계약을 구현해야 한다.
- 실행 중 인증·정책·위임/승인 만료·취소를 커밋 알림 및 `RecheckInterval`(기본 1초, 최대 30초)마다 다시 확인한다. 다른 복제본의 알림이 없어도 주기적으로 감지한다. provider는 context 취소를 준수해야 한다.
- `gate.NexusAuth`는 verifier 저장소 기반 licence/login/agent 인증 어댑터다. 현재 자격증명 저장소는 메모리이며 운영 등록·메일·패스키·키 회전은 미구현이다.
- 일반 메시지 `POST /v1/messages`, 세션 탐색·이름·heartbeat·presence 정리, 계획/작업 조회·Reparent API가 추가됐다. Inbox는 신뢰된 일반 메시지와 배정을 모두 반환한다. TUI 수신은 별도 opt-in polling 구현이며 로그인/송신 UI 전체 연결을 의미하지 않는다.

### 이번 재검증

- Go 1.24.2: `TMPDIR=/tmp go test -race -count=1 ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...` 통과. WSL `/mnt/c` 임시 디렉터리는 POSIX 권한 테스트에 부적합하여 `/tmp`를 사용했다.
- 호스트 포트/외부 네트워크가 없는 폐기용 PostgreSQL 17에서 `go test -race -count=1 -timeout=240s ./nexus/pgstore` 통과. 신규 영구 실행 suite를 실제/강제 재시도 Postgres 모두 실행했다.
- 확장된 suite에서 발견한 테스트 fixture pool 누적/100 connection 한도 소진을 수정했다. 각 subtest 종료 시 pool을 닫고 스키마 정리 연결은 정리할 때만 연다.
- HTTP 승인 재시작, 다른 API 복제본 취소, 자격증명 철회/위임 만료 감지, panic 보수 정산 및 Gate 계정/세션 결속 테스트 통과. 외부 Supabase·Cloudflare·유료 모델 호출은 하지 않았다.

## 연결 계약

- `Config.Authenticate`가 인증정보의 무결성·만료·철회를 검사하고 `nexus.Principal`을 반환한다. HTTP 본문의 주체·사용량·승인 값은 신뢰하지 않는다. 시스템 주체는 거절한다.
- `Actions`는 서버 설정인 `action → 고정 토큰 비용`이다. 실제 모델 토큰 정산이 아니다.
- `POST /v1/executions/{invocation}` 본문은 `delegation_id`, `action`, `args`뿐이다. 승인 시 공백을 제거한 args의 SHA-256에 결속되며 키 순서/숫자 표기는 구별한다.
- 사람 승인만 지원한다. 승인 결과는 프로세스 메모리에 있고 TTL과 단일 상태 전이를 갖는다. 실행 직전에 정책을 다시 검사한다. 위임 범위 확장·상시 승인·메일·패스키 승인은 아직 아니다.
- `BeginExecution`은 정책 확인·고정 비용 차감·시작 영수증을 한 트랜잭션에 기록한다. 일치하는 재요청은 다시 실행하지 않는다. 다른 매개변수는 충돌한다.
- 서버 재시작 후 시작 영수증만 있으면 `indeterminate`로 반환한다. 외부 부작용의 exactly-once 보장이 아니라 **재실행 방지**다. 실패/취소/잘못된 runner args에도 이미 기록한 고정 비용을 환급하지 않는다.
- 결과·승인 레코드는 `MaxRecords`로 제한되며 자동 제거하지 않는다. 프로세스 재시작 시 소실된다. 운영용 복구·보관 정책은 후속 구현이다.
- HTTP 응답과 실행 원장은 상태·입력 해시만 기록하며 args·runner 출력·오류 본문은 반환하지 않는다. redact는 알려진 문자열 패턴만 탐지하며 임의 JSON 비밀 필드/미지의 비밀을 모두 탐지하지 않는다.
- SSE는 `Last-Event-ID`/`after` 커서를 지원하고 알림·heartbeat마다 자격을 다시 확인한다. 이미 전송한 데이터는 회수하지 않는다.

## 실제 Core 연결

`NewCoreRunner(CoreRunnerConfig{Service, Model, ModelName, WorkDir})`의 반환값을 `Config.Run`에 넣고 `Actions`에 `model:<ModelName>` 고정 비용을 지정한다.

- 각 승인된 invocation마다 **실제 `core.Engine`**을 새로 생성한다. 테스트의 `Model`만 fake다.
- args는 `{"message":"..."}`만 허용한다. 클라이언트의 model/work_dir/session_id/prompt_type은 거절한다.
- 검증된 actor/delegation/invocation/승인 상태는 HTTP 내부 context 값으로 전달한다. Runner를 context 없이 직접 호출하면 거절한다.
- model call마다 위임 정책과 승인 TTL을 재검사한다(재시도 포함). 모델·작업 디렉터리는 서버가 정한다. 모델 구현은 동시 호출 및 context 취소를 준수해야 한다.
- 모델 전용, ask 모드, 한 라운드, 메모리 세션이다. toolset·secret·임의 Binder·디스크 기록을 주입하지 않는다. Core 자체 재시도는 발생할 수 있다.
- `Binding.Session`만 Nexus 세션으로 전달한다. 로컬 conversation은 invocation에서 분리 생성한다. Core TaskID는 아직 임시 생성 값이며 정식 Nexus Task 매핑/대화 재개는 미구현이다.
- HTTP 취소는 `Engine.Cancel`로 전파하고 이벤트 채널을 끝까지 배출한다. content/error 이벤트는 HTTP에 내보내지 않는다.
- TUI Binder/로컬 `/sessions`·`/load`와는 별개다. 도구 승인 UI나 원격 탐색을 연결한 상태가 아니다.

## 검증 구분 (2026-10-01)

### 로컬에서 실제 실행

- Go 1.24 + 폐기 가능한 Docker PostgreSQL 17(호스트 포트 미공개).
- `conformance.RunExecution`을 기존 `conformance.Run`에 연결: 메모리, 강제 재시도 메모리, 실제 Postgres, 강제 재시도 Postgres에서 동일 계약 확인.
- 24개 동시 시작의 영수증/사용량 한 번 기록, 서비스 재생성 후 중복 차단, hash/action/cost 충돌, 한도·만료·철회·주체 및 16진수 해시 검증.
- HTTP 경계와 실제 Core 엔진 실행, 취소, 대화 격리, 오류 비노출.
- 로컬 loopback HTTP SSE 커서 재개와 인증 무효화 시 종료.

### fake/mock 의존성으로만 검증

- HTTP 인증자는 테스트용 주체를 반환한다. 실제 Gate 로그인 토큰 서명·키 회전 검증은 아니다.
- Core 모델은 fake이며 provider HTTP/실제 과금/실제 모델 응답 품질은 검증하지 않는다.
- HTTP 승인자는 테스트용 사람 자격이다. 메일·패스키 경로는 연결하지 않았다.

### 후속 구현 / 스테이징 필요

- Gate 인증·영구 승인·usage 예약/실측 정산·실제 Core tool 권한/비밀/승인 Binder.
- Supabase TLS/세션 모드·운영 권한, Cloudflare Container/Worker 프록시·SSE 타임아웃, R2 다운로드.
- 실제 이메일 승인→설치, 모델 제공자, 다중 프로세스 복구 및 배포 수명주기.
- 운영 DB·Supabase 마이그레이션·외부 유료 호출·배포는 이번 작업에서 실행하지 않았다.

## Binder 확장 전 차단 경계

현재 Binder는 `Binding.Session`만 채운다. 아래는 **도구 Binder를 구현하기 전의 필수 계약**이며 구현 완료 선언이 아니다.

| 경계 | 현재 동작 / 확장 조건 |
|---|---|
| 신원 | actor/delegation/invocation은 인증된 HTTP 내부 context에서만 전달. `BindRequest.Conversation/Task/Message`는 권한 증거가 아니다. |
| 모델 승인 | 외부 `model:<name>`의 정확한 입력에만 적용. 도구 이름·인자·다른 모델이나 비밀 접근으로 확대하지 않는다. |
| 도구 Gate | 현재 도구는 아예 바인딩하지 않는다. 확장 시 서버가 `tool:<name>` 및 정확한 args를 다시 검사하고 승인해야 한다. Core의 `Binding.Tools`는 일반적으로 builtin Gate 경로를 타지 않으므로 보안 검사가 필요한 도구에는 `RequiresGate` 또는 동등한 자체 검사를 반드시 적용한다. |
| 비밀 | `Binding.Secret`는 nil이다. 확장 시 별도 `secret:NAME` 정책 검사 후 도구 실행 경계에서만 해석하며 프롬프트·로그·SSE에 값을 싣지 않는다. 현재 redact가 탐지하는 `secret://LOCAL_TEST` 같은 참조도 HTTP 입력에서 거절된다. 이 패턴 탐지는 임의 비밀 전체에 대한 보장이 아니다. |
| 만료·철회 | 매 provider 호출 직전 위임 상태 및 승인 만료를 검사한다. 이미 진행 중인 호출을 TTL/철회 즉시 중단하는 감시기는 없으며 다음 재시도만 차단한다. 실시간 중단은 후속 구현이다. |
| 취소 | 요청 context 또는 `/cancel`이 Core 취소로 전파된다. provider는 context를 준수해야 한다. 이미 시작한 비용은 환급하지 않고 같은 invocation은 재실행하지 않는다. |
| 비용 | Core 재시도 횟수와 무관하게 외부 invocation의 고정 비용 한 번만 차감. 실측 provider 토큰 비용을 정확히 정산한다는 뜻이 아니다. |

### 후속 로컬 회귀 검증

- `core_boundary_test.go`: 실제 Core 엔진 + fake 모델에서 재시도 중 승인 TTL/위임 만료/철회/중지/요청 취소, 취소된 승인 무차감, 재요청 중복 차감 차단.
- 승인된 모델이 `run_command/read_file/secret_input/mcp_external` 호출을 반환해도 실행 능력을 얻지 못하고 `failed`로 종료.
- 클라이언트의 tools/binder/secret/active_files/approved/agent_session_id 주입 거절 및 도구 인자·비밀 참조의 원장 비노출.
- Docker Go 1.24, 네트워크 차단 상태: HTTP race 10회, 전체 race 1회·vet·CGO 없는 빌드 통과. 이번 후속 검증에서는 DB DSN을 설정하지 않아 **Postgres 통합 시험은 skip**이다. 위의 과거 폐기용 PostgreSQL 검증과 구분한다.

## 작업 배정 Inbox (`5518c34`, 0.4.17)

- `GET /v1/inbox?after=<seq>&limit=<1..100>`는 인증된 봇 자신의 배정만 `{messages, next}`로 반환한다. 사람·system은 거절한다. 0/100 초과 limit는 100, 음수/잘못된 숫자는 오류다.
- `Delegate(to_session_id)`는 받는 세션에 `task.assigned`와 `inbox: true`를 같은 트랜잭션에서 기록한다. 새 세션은 초기 작업으로 시작하므로 Inbox에서 제외한다.
- `Received`는 `task_id/title/text(brief)/delegation_id/from/relation=delegator`를 담는다. 이는 실행 허가가 아니며 받은 쪽이 위임·정책을 다시 확인해야 한다.
- `ForInbox`는 신뢰된 `hub` 출처만 배정으로 인정한다. 클라이언트가 `bot`/`engine` 출처로 같은 kind를 써도 Inbox에 들어가지 않는다.
- 세션 SSE는 커밋 알림으로 배정을 전달한다. 클라이언트는 `ForInbox`와 동등한 필터로 깨운 뒤 Inbox를 읽고 `next`를 보존해야 한다. Mirror/TUI 바인딩은 아직 없다.
- **초기 Inbox는 배정 전용이었다.** 후속 구현에서 일반 `Send`/`SendTo`와 관계 계산을 추가했다. 임의 클라이언트 `message` 이벤트는 여전히 신뢰 메시지로 노출하지 않는다.
- 메모리·강제 재시도 및 폐기용 PostgreSQL 17에서 수신/발신 격리·새 세션 제외·위조 차단·500개 비배정 사건 이후 페이지/재개를 검증했다. 로컬 HTTP에서 SSE 깨움과 Inbox, 인증·쿼리 경계를 검증했다.
- Docker Go 1.24로 `go test -race ./nexus/... ./conformance -count=3 -timeout=180s`, 해당 패키지 vet·CGO 없는 빌드 통과. DB는 호스트 포트/외부 네트워크 없이 생성 후 제거했다. Supabase/배포 검증이 아니다.

## 재검증

Go 1.24 이상과 스키마 생성/삭제 가능한 **폐기용** Postgres DB를 사용한다.

```sh
# NTS_NEXUS_TEST_DSN을 폐기용 로컬 DB로 설정한 상태
# 미설정이면 pgstore 통합 시험은 skip이며 DB 검증 성공으로 세지 않는다.
go test -race ./nexus/... ./conformance -count=3 -timeout=180s
go test -race ./... -count=1 -timeout=240s
go vet ./...
CGO_ENABLED=0 go build ./...
```
