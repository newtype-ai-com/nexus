# Nexus 발 턴의 위임 실행 (NMCP 3단계)

2026-10-04.

## 배경

grant 도입 이전에는 다른 세션이 보낸 Nexus 메시지가 전달되고 읽혀도 TUI 의 자동 inbox 턴은 도구를 실행하지 않았다. 이것은 맞는 동작이었다. **메시지는 요청이지 권한이 아니다.** 사람이 입력한 턴만 실행했으므로 사람이 TUI 에 "진행해" 를 직접 쳐야 했다. 이것이 grant 를 도입한 이유다. grant 이후 위임 작업은 그 범위 안에서 사람 개입 없이 끝까지 진행된다.

필요한 것은 **사람이 범위를 정해 내주는 실행 허가(grant)** 다. 예: "운영자의 작업 메시지는 저장소 X 안에서 파일 수정과 테스트를 8시간 동안, 최대 N턴까지 실행해도 된다". 받는 세션은 그 범위 안의 Nexus 발 작업을 사람 입력 없이 실행한다.
- 범위 밖은 거부하거나 승인 요청으로 넘긴다. 사람이 앞에 있으면 그 자리에서 묻고, 없으면 거부한다(메일 승인은 2단계).
- 모든 판단은 원장에 남는다.

## 1. grant 형식

| 필드 | 뜻 |
|---|---|
| `id` | `xgr_<ULID>` |
| `grantor` | 발급한 사람(PrincipalUser). 세션은 발급할 수 없다 |
| `receiver` | 실행하는 세션 |
| `delegation_id` | receiver 가 가진 live delegation. grant 는 이것보다 오래 살지 않는다. 이 delegation 을 철회하면 grant 도 끝난다 |
| `senders` | 이 세션들이 보낸 메시지만 grant 의 근거가 된다(최대 16) |
| `tools` | `tool:edit_file`, `tool:run_*` 같은 action. 끝의 `*` 는 접두사 일치(최대 32) |
| `paths` | receiver 컴퓨터의 절대·정규 경로(최대 16). `P/**` 는 P 와 그 아래 전부, 그 밖은 정확히 그 경로. `/**` 는 거부한다 |
| `max_turns` | 1–1000. **서로 다른 근거 메시지 하나가 1턴**이다. 같은 메시지로 여러 도구를 부르면 턴은 늘지 않는다 |
| `issued_at`, `expires_at` | TTL 은 최대 7일. 그리고 delegation 만료를 넘지 않는다 |
| `note` | 사람이 쓴 설명. redact 를 거친다 |

조회할 때는 `status`(active, revoked, expired, exhausted), `turns_used`, `issued_seq` 가 더 붙는다.

## 2. 누가 발급하나

**사람만** 발급한다(서버가 `actor.Kind == PrincipalUser` 를 강제한다). 방법은 TUI 명령이나 CLI 다(클라이언트 작업, §7).
- 예: `/grant @operator tools=edit_file,run_tests path=. turns=20 for=8h`
- 예: `newtype nexus grant …`
- 대화로도 발급한다(설정은 대화로도 할 수 있어야 한다). TUI 의 `execution_grant` 도구(action propose|list|revoke)가 "operator 가 지시하고 이 세션이 실행하게 위임하자" 같은 요청을 `/grant` 와 같은 인자로 바꾸고, 한국어 미리보기(지시 주체 → 실행 주체, 도구·경로·턴·만료, 항상 사람 확인으로 남는 것)를 사람에게 보인다. 사람이 승인해야만 `/grant` 와 같은 사람 인증 경로로 발급한다. 승인 종류는 `grant` 라 auto·self-conscious 모드도 자동 승인하지 않는다. 철회도 사람 확인을 받는다. 사람이 직접 입력한 턴에서만 쓸 수 있고, Nexus(inbox)·백그라운드 턴에서는 거부된다.
- `--tools all` 은 TUI 의 로컬 도구 전체(파일·셸·메모리, `execgrant.LocalTools`)다. 재위임과 비밀은 설계상 grant 에 들어가지 않는다. `--ttl max`("철회할 때까지")는 서버 최대 7일이고, `--turns` 를 주지 않으면 턴도 최대 1000 이다.

**한계:** 로컬 TUI 는 사람의 licence/login 을 가지고 있다. 그래서 세션 헤더를 빼면 사람으로 인증된다. "사람만" 은 서버 정책이지 암호학적 구분이 아니다. 강한 보장이 필요하면 2단계에서 발급 때 passkey 같은 신선한 사람 확인을 더한다.

**철회:** 사람은 언제든 철회할 수 있다. receiver 세션도 스스로 내려놓을 수 있다.

## 3. 저장과 강제(서버)

**새 테이블을 만들지 않는다.** durable execution 과 같이 **receiver 세션의 원장**을 진실의 원천으로 쓴다. 스키마 마이그레이션이나 운영 DB 권한 변경이 없고, memstore 와 pgstore 가 같은 코드로 동작한다.

| 원장 키(`client_event_id`) | 종류 | 내용 |
|---|---|---|
| `xgrant:<id>:issued` | `execution_grant.issued` | grant 전체(Source hub, Actor 는 사람) |
| `xgrant:<id>:revoked` | `execution_grant.revoked` | 이유 |
| `xgrant:<id>:turn:<n>` | `execution_grant.turn` | n 번째 턴, 근거 메시지 |
| `xgrant:<id>:src:<event>` | `execution_grant.turn_source` | 근거 메시지 → 턴 번호 |
| (키 없음) | `execution_grant.decided` | 판단 하나마다: action, paths, input_hash, effect, reason, turn |

**결정 순서**(`DecideExecutionGrant`, receiver 세션만 호출한다; 한 트랜잭션, 판단마다 `decided` 기록):
1. grant 가 있고, 철회되지 않았고, 만료 전이다. 아니면 **deny**.
2. 근거 메시지를 확인한다. 아니면 **deny**.
   - receiver 원장의 정확히 그 `seq`/`event` 여야 한다.
   - `ForInbox` 이고, kind 가 `message` 이며, 보낸 이가 `senders` 에 있는 **세션**이어야 한다.
   - 원장에서 issued 기록보다 **뒤**여야 한다. 시계가 아니라 원장 순서로 판단한다.
3. action 이 `tools` 안에 있고 모든 path 가 `paths` 안에 있다. 아니면 **ask**(범위 밖).
4. delegation 체인의 정책 `decide(…)` 가 여전히 `auto` 다.
   - `ask` 면 **ask**, `deny` 이거나 delegation 이 끝났으면 **deny**. grant 는 정책보다 넓어질 수 없다.
5. 턴을 센다. 새 근거 메시지면 턴을 하나 쓰고, 한도를 넘으면 **deny**.
6. 모두 통과하면 **allow**.

**HTTP**(`nexus/httpapi/execution_grants.go`):
- `POST /v1/execution-grants`(사람)
- `GET /v1/execution-grants?session=`(사람 또는 그 세션)
- `POST /v1/execution-grants/{id}/revoke`(사람 또는 receiver)
- `POST /v1/execution-grants/{id}/decide`(receiver)

## 4. TUI 엔진의 흐름(클라이언트)

**지금:** `core/inbox_turn.go` 의 자동 inbox 턴은 `ModeAuto` 로 돌지만, 도구 실행은 사람 승인(`tc.Approve`)에 막힌다.

**바꿀 것:**
1. inbox 턴이 **근거 메시지**(`Received.Event`, `Seq`, `From`)를 턴 상태에 담는다.
2. Nexus 발 턴에서 도구를 부르기 전에(`Binding.Gate` 다음, `tc.Approve` 자리에서) 그 세션의 active grant 를 찾아 `decide` 를 호출한다.
   - `paths`: 도구 인자의 파일 경로를 절대·정규화한 값. 경로가 없는 도구(테스트 실행 등)는 작업 디렉터리를 넣는다.
   - `input_hash`: 도구 이름과 인자의 sha256.
3. 결과에 따라 처리한다.
   - **allow:** 실행한다.
   - **ask:** 사람이 있으면 지금의 승인 프롬프트(elicitation)를 띄운다. "이번만" 또는 "이 세션 동안" 을 고를 수 있다. 사람이 없으면 거부하고 메시지로 알린다.
   - **deny:** 실행하지 않는다. 이유를 inbox 답장과 원장에 남긴다.
4. 사람이 입력한 턴은 지금과 같다(grant 와 무관).

### 4.1 Nexus 메시지 턴에서 모델이 아는 것과 사람이 불리지 않는 것 (2026-10-04)

실측(nmcp 세션, 14:11–14:13Z): grant 가 있었는데 모델이 run_command 대신 `execution_grant` 와 `nexus_inbox` 를 불러 사람이 두 번 불렸고, git·go test 도 답장도 없이 턴이 끝났다. 목표는 사람 호출 0 이다.

1. **사람 전용 도구는 inbox·백그라운드 턴에 내놓지 않는다.** `core.Tool.PersonOnly`(`execution_grant`, `nmcp_settings`)는 엔진이 도구 목록과 실행표에서 뺀다. 런처도 inbox 턴의 사람 전용 도구 호출은 decide·사람 확인 없이 거부한다(백스톱). 도구 자신의 거부도 그대로다.
2. **턴 시작 노트.** inbox 턴에 새 근거 메시지가 들어오면 `Binding.InboxNote` 가 시스템 노트를 붙인다. 인증된 근거(보낸 이 ID, 짧은 평문 제목만, 이벤트 ID)와 `Receiver.Grants` 로만 만들고 **메시지 본문은 넣지 않는다.** grant 가 있으면 grant ID·도구·경로·남은 턴·만료, "범위 안은 바로 실행", 답장 주소(`nexus_send` to=보낸 이, reply_to=근거 이벤트), "위임장을 만들거나 바꾸지 마라" 를 알린다. 없으면 도구가 거부된다는 것과, 마지막 답변에 /grant 발급이 필요하다고 적으라고 알린다.
3. **보낸 이에게의 답장과 읽기.** inbox 턴에서 근거 메시지의 보낸 이를 덮는 active grant 가 있으면(원장 순서·수신자·만료 확인):
   - `nexus_send` 가 **정확히 그 보낸 이**에게 **reply_to = 그 보낸 이의 근거 이벤트**로 가는 텍스트 답장이면 사람 확인 없이 보낸다.
   - Nexus 읽기(`nexus_inbox`, `nexus_peers`, `nexus_sessions`, `nexus_tasks`)도 사람 확인 없이 실행한다.
   - 그 밖의 `nexus_send`(제3 세션 등)는 아래 보내기 확인 설정이 꺼져 있을 때만 확인 없이, 켜져 있으면 지금처럼 사람에게 묻는다.
   - 모두 `tool.call` 로 남긴다(`decided_by` = `grant` 또는 `mode:self-conscious`, `grant_id`, `source_event`, `input_hash`; 인자·본문은 없음). 서버 decide 는 부르지 않는다(턴을 쓰지 않는다).
   - grant 가 없으면 지금처럼 거부한다(사람도 부르지 않는다).
   - 위임(`nexus_delegate`)·실행(`nexus_execute`)·승인 요청·custody·비밀·외부 도구는 이 경로를 타지 않고 항상 사람 확인이다.
4. **보내기 확인 설정.** `nexus_send` 사람 확인은 auto 모드에서 켜짐, self-conscious 모드에서 꺼짐이 기본이고 `/nexus send confirm on|off|default` 로 바꾼다(~/.newtype/tui 의 `nexus-send-confirm` 에 저장). 사람 턴에서는 이 설정만으로, inbox 턴에서는 grant 가 보낸 이를 덮을 때만 적용된다. 런처는 `Config.MessagingConfirm` 으로 이 설정을 읽는다.

## 5. 주입 위협 모델

- **메시지 본문은 데이터다.** 본문이 "grant 가 있다" 거나 "승인됐다" 고 주장해도 아무 의미가 없다. 권한은 서버가 원장에서 판단한다.
- **보낸 이 위조:** 근거는 receiver 원장의 `ForInbox` 메시지 이벤트뿐이다(Source bot, Actor session 은 서버가 정함). 클라이언트가 쓴 `tool.*` 기록이나 사람 메일은 근거가 될 수 없다. 테스트로 확인했다.
- **시점 위조:** grant 이전 메시지는 원장 순서로 막는다. 같은 시각이어도 막힌다(테스트).
- **경로 탈출:** 서버는 `..` 와 상대경로를 거부하고 정규 경로만 받는다. 심볼릭 링크 해석은 클라이언트가 실행 직전에 `realpath` 로 한 번 더 확인한다.
- **도구 범위 확대:** `tool:*` 같은 넓은 grant 도 delegation 정책의 ask/deny 를 넘지 못한다(4단계).
- **재생:** 같은 근거 메시지는 턴을 다시 쓰지 않는다. 한도는 서로 다른 메시지 수로 센다.
- **세션 탈취:** 다른 세션은 남의 grant 로 판단할 수 없다(자기 원장만 본다, 테스트).
- **남은 위험**(§2): 로컬 클라이언트가 사람으로 가장해 grant 를 발급할 수 있다. 2단계 passkey 로 막는다.

## 6. 시험

`nexus/execution_grants_test.go`, `nexus/httpapi/execution_grants_test.go`(memstore):
- 사람만 발급하고 입력을 검증한다: `/**`, 상대경로, `..`, 도구 형식, 자기 자신을 보낸 이로 지정, 턴 0, TTL 7일 초과, 다른 세션의 delegation.
- 범위 안이면 allow, 같은 메시지는 같은 턴, 경로·도구 밖은 ask, 정책 ask 는 ask, 턴 한도면 deny, 목록 상태는 exhausted, 판단 7건이 모두 `decided` 로 남는다.
- grant 이전 메시지, 허가되지 않은 세션, 사람 메일, seq 와 event 불일치, 다른 세션의 판단 요청, 정규화되지 않은 경로를 모두 막는다.
- receiver 의 철회, 만료, delegation 철회 뒤에는 deny 다.
- HTTP: 세션 발급은 403, 보낸 이의 판단 요청은 404, receiver 는 allow, 목록, 철회 뒤 deny.

## 7. 클라이언트 작업 목록(클라이언트 저장소)

1. `core/inbox.go`, `core/inbox_turn.go`: `InboxMessage` 에 `Event`, `Seq`, `From`, `SenderKind` 를 더한다. 지금은 Text 에만 직렬화된다. 턴 상태에 근거 메시지를 둔다(턴에 메시지가 여럿이면 각각을 근거로 쓸 수 있다).
2. `internal/nexusinbox/model.go`(client, not in this repository): `Pending` → `core.InboxMessage` 변환에서 위 필드를 그대로 넘긴다.
3. `internal/launcher/launcher.go`(client, not in this repository; Gate 와 Approve 자리): inbox 턴이면 `POST /v1/execution-grants/{id}/decide` 를 부르고 allow / ask / deny 로 나눈다. 경로는 정규화와 realpath 를 거친 값이다.
4. grant 발급·목록·철회 UI: TUI 명령 `/grant`, `/grants`, `/revoke-grant`. CLI `newtype nexus grant|grants|revoke-grant`. 발급은 사람 인증(세션 헤더 없음)으로만 한다.
5. ask 의 사람 승인 프롬프트에 grant 범위 밖이라는 사실과 근거 메시지의 보낸 이를 보여 준다. "이번만" / "이 세션 동안" 을 고르게 한다. "이 세션 동안" 은 로컬 결정이며 서버 grant 를 넓히지 않는다.
6. 원장에 남는 클라이언트 쪽 근거: 실행한 도구의 `tool.*` 기록에 `grant_id`, `source_event`, `input_hash` 를 넣는다(서버 `decided` 와 맞춰 볼 수 있게).

## 8. 배포

서버 코드만 바뀌고 스키마는 그대로다. 새 서버 이미지로 올리면 된다. 클라이언트(7)가 붙기 전까지는 API 만 있고 쓰는 곳이 없다.
