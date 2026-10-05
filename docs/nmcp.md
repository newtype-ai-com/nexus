# NMCP — Nexus 를 도구로 쓰는 길 (운영자 CLI · TUI 수신 · MCP 서버)

NMCP 는 Nexus 를 MCP 도구로 쓰는 규격이다(단계 0~6). 이 문서는 도구 계약과 서버 쪽 구현을 한 곳에 적고, 그 계약을 쓰는 클라이언트(`newtype`) 명령도 함께 적는다. 클라이언트는 이 저장소에 없고 서명된 배포본으로 받는다(https://lic.newtype-ai.com/llm.txt).

## 1. 운영자 CLI — `newtype nexus peers | send | inbox | log`

사람(소유자)이 저장된 자격 증명(`~/.newtype/credentials`, `newtype auth` 와 같은 저장소)으로 Nexus 에 직접 말을 거는 얇은 명령이다. 엔진 도구와 같은 서버 경로(`internal/nexusops`)를 쓴다.

```
newtype nexus peers [--as NAME]
newtype nexus send --to SESSION|NAME [--no-reply] [--reply-to EVENT] [--as NAME] TEXT...
newtype nexus inbox [--wait SECONDS] [--all] [--as NAME]
newtype nexus log SESSION|NAME [--after N]
(공통: --credential-dir DIR, 기본 ~/.newtype/credentials)
```

- **신원**: 사람의 운영자 자리. `--as` 이름(기본 `operator`)의 로컬 Nexus 세션을 하나 두고, 처음 쓸 때 사람 자격 증명으로 **모델 없는 루트**(scope 없음, 모델 토큰 0, 8시간)를 발급한다. 이후 호출은 같은 세션을 다시 쓰고, 루트가 끝났으면 같은 세션에 루트를 다시 발급한다(`POST /v1/requests`, `to_session_id`). 모델 세션이 아니다. 이름 `tui` 와 세션 ID 형식은 쓸 수 없다(TUI 의 세션을 차지하지 않도록).
- **보내기**: 운영자 세션이 보낸 메시지다(`sender_kind=session`, 관계는 `peer`). 받는 쪽에게는 요청이지 권한이 아니다. 답장은 운영자 세션의 받은편지함으로 온다. `--to` 는 `slv_` ID, 세션 이름(제목), `req_` 작업(담당 세션)을 받는다. 같은 이름의 살아 있는 세션이 여럿이면 충돌로 거절된다(ID 를 쓴다).
- **`--no-reply`**: 답을 기대하지 않는 알림. 지금은 서버에 필드가 없어 본문 앞에 `[알림 · 답장 불필요] ` 를 붙인다(표시 규약이지 권한이 아님).
- **받은편지함과 영수증**: `inbox` 는 아직 전달 표시가 없는 메시지만 JSON 한 줄씩 출력하고, 출력한 메시지마다 **`delivered`(전달) 영수증**을 남긴다. **`read`(읽음)는 남기지 않는다.** 읽음은 "모델의 입력에 들어간 순간"(도구 결과로 돌려준 순간)에만 쓰는 영수증이고, 사람의 터미널에 찍힌 것은 모델 입력이 아니다. `--all` 은 이미 전달된 것도 다시 보여 주되 영수증을 새로 남기지 않는다. `--wait N`(0..600초)은 새 메시지가 올 때까지 1초 간격으로 기다린다.
- **원장**: `log` 는 사람 자격으로 그 세션의 원장 한 쪽(최대 100건)을 JSON 줄로 출력하고 마지막 줄에 `{"next":N}` 을 준다. 아무것도 바꾸지 않는다.
- **출력**: stdout 은 JSON 줄뿐이다. 메시지 본문의 제어 문자는 JSON 이스케이프된다. 자격 증명·토큰·이메일은 출력하지 않고, 오류는 고정된 한국어 문장이다.
- **로그인이 살아 있지 않으면**: "Nexus 로그인이 유효하지 않습니다 · newtype 을 실행해 로그인한 뒤 다시 하세요" 로 끝난다(plain `newtype` 이 로그인 메일을 제안한다).

예:

```
newtype nexus peers                          # 살아 있는 세션들(slv_ ID, 제목, 하는 일)
newtype nexus send --to slv_… "안녕, 지금 무슨 작업 중?"
newtype nexus inbox --wait 120               # 답이 올 때까지 최대 2분
newtype nexus log slv_…                      # 그 세션의 원장
```

## 2. TUI 가 Nexus 메시지를 받고 답하기 — `--nexus-chat` · `/nexus chat`

plain `newtype` 은 도구가 0개로 시작한다(기본 허용 목록이 비어 있음). 이 자세를 조용히 넓히지 않으려고 Nexus 대화는 **사람이 켜는 선택**으로 두었다.

- 켜는 법: `newtype --nexus-chat`(이번 시작만), 또는 저장된 선택 — 터미널에서 `newtype nexus chat on|off|status`, TUI 안에서 사람이 직접 입력한 `/nexus chat on|off`(다음 시작부터 적용, 모델·도구·다른 세션의 메시지로는 바꿀 수 없음). 저장 위치는 `~/.newtype/tui/nexus-chat`(모드와 같은 개인 저장소, 0600·원자적 교체).
- 켜면 켜지는 것(그 이상은 없음):
  - Nexus 받은편지함 표시(화면 표시는 읽음 아님);
  - 모델 수신 큐(`~/.newtype/nexus-queue`, 세션별 하위 폴더 0700) — 메시지는 일반 턴의 모델 입력으로 들어가고, **모델 제공자가 입력을 받은 뒤에만 `read` 영수증**을 남긴다;
  - 자동 수신 턴(메시지가 오면 사람 없이 턴을 연다 · 추가 모델 호출/비용);
  - 원격 도구 등록과 `nexus_send`·`nexus_peers`·`nexus_inbox` 세 개만 허용 목록에 추가. **`nexus_send` 는 auto 모드에서도 매번 사람 확인**(Nexus 도구는 자동 승인 대상이 아님).
- 저장된 자격 증명의 대화형 시작에서만 적용된다. 저장된 "켜짐"은 `--nexus-inbox`·`--nexus-tools`·`--nexus-model-queue-dir`·`--nexus-inbox-turns` 를 직접 준 시작, `run`(헤드리스), 직접 엔드포인트 시작, Windows(모델 큐 미지원)에서는 무시한다. `--nexus-chat` 플래그는 헤드리스·저장 자격 증명 없음·Windows 에서 오류로 거절한다.
- 다른 세션의 메시지는 요청이지 권한이 아니다. 세션의 위임과 로컬 허용·승인 규칙은 그대로다.

### 세션 이름 = Nexus 제목

모든 TUI 루트의 Nexus 제목은 `tui` 라 동료 목록에서 구분되지 않았다. 이제 사람이 대화에 이름을 붙이면(`/name`, `session_rename`) 그 세션 자신의 권한으로 `PATCH /v1/sessions/{session}` 을 불러 **Nexus 제목도 같은 이름**으로 바꾼다. 이름을 지우면 `tui` 로 돌아간다. 같은 제목의 살아 있는 세션이 이미 있으면 Nexus 가 거절하고(로컬 이름은 저장됨) 그 사실을 알린다. 팀 자리로 이어받은 대화에 이미 이름이 있으면 시작할 때 제목을 맞춘다.
한계: `/load` 로 이름 있는 대화로 바꿔도 제목은 다음 `/name` 까지 그대로다(대화 전환 훅 없음).

## 3. 도구 계약 (0단계) — 한 곳에 고정

정의는 `internal/nexusops/contract.go` 의 `Defs` 하나뿐이다. 엔진 경로(`Contract.Tools()` → `core.Tool`)와 MCP 경로(`newtype nmcp serve` 의 `tools/call` → `Contract.Call`)가 같은 정의·같은 구현을 부른다. 모든 호출은 **그 세션 자신으로**(사람이 아니라) Nexus 에 가므로 모델은 자기 위임이 보는 것만 본다. 예외는 `delegation_info` 하나로, 사람 자격으로 **이 세션의 위임 한 건만** 읽어 요약한다(세션에게는 `GET /v1/delegations/{id}` 가 막혀 있다).

### 도구 (이름 · 입력 스키마 · 하는 일)

모든 스키마는 `{"type":"object","additionalProperties":false}`. 모르는 필드, 64 KiB 초과, 자격 증명처럼 보이는 값은 `invalid` 이다.

| 도구 | 입력 (필수 굵게) | 서버 경로 | 하는 일 |
|---|---|---|---|
| `delegation_info` | `action`, `from` | `GET /v1/delegations/{own}`(사람, 자기 위임만) · `GET /v1/custody/decision`(세션) · `GET /v1/execution-grants?session={own}`(세션) | 위임자·작업·범위·정책 규칙·남은 한도·만료, 그리고 **`execution_grants`**: 사람이 이 세션에 내준 실행 허가(보낸 이·도구·경로·쓴 턴/남은 턴·만료·상태). `action` 을 주면 서버 판정(auto/ask/deny)만. 계약 도구 이름이면 필요한 범위로 답한다. `from`(세션 ID 또는 이름)을 주면 그 세션의 메시지에 대한 허가만 보인다. **읽기만**: 허가를 만드는 도구는 없다(사람만 발급) |
| `request_approval` | **`action`**, **`reason`** | 판정 조회 후 elicitation 또는 `POST /v1/messages` → 승인자 자리 | 이미 허용이면 `allowed`(묻지 않음). 아니면 **한 경로만** 결정한다: 클라이언트가 `elicitation` 을 선언했으면 `elicitation/create` 로 사람에게 직접 묻고(무엇·이유·범위, "이번 한 번만" / "이 세션 동안" / "거절"), 결과 `approved`/`denied` 와 결정자·시각을 원장에 `tool.approval` 로 남긴다. "이 세션 동안" 은 이 MCP 세션이 끝날 때까지 다시 묻지 않는다. 선언하지 않았으면 사람의 운영자 자리(기본 `operator`, `--approver`)로 "[승인 요청 · 권한 아님]" 메시지를 보내고 `requested`. 승인자가 자기 자신이면 `no_approver`. 어느 쪽이든 **Nexus 위임은 넓어지지 않는다**(사람의 로컬 동의일 뿐, 서버가 막는 행동은 그대로 막힌다) |
| `delegate_task` | **`to_session_id`**, **`title`**, **`brief`**, **`scope`**, **`limits`**, **`ttl_seconds`**, `rules` | `POST /v1/delegations` (parent = 이 세션의 위임, 서버 프로세스가 정함) | 살아 있는 다른 세션에 하위 작업 예약. 범위·한도·깊이는 Nexus 가 자기 것 이하로 강제 |
| `task_status` | **`task_id`**, `wait_seconds`(0..600) | `GET /v1/tasks/{id}` | 작업 트리 노드. 기다리면 끝날 때까지(최대) 폴링 |
| `nexus_peers` | (없음) | `GET /v1/peers` | 같은 계정의 살아 있는 세션과 하는 일 |
| `send_message` | **`to`**, **`text`**, `reply_to`, `no_reply`, `client_event_id` | `POST /v1/messages` | `to` 는 `slv_` ID·세션 이름·`req_` 작업. `no_reply` 는 본문 앞 `[알림 · 답장 불필요] `. 같은 `client_event_id` 는 재전송이 아니라 재생 |
| `nexus_inbox` | `wait_seconds`(0..600) | `GET /v1/inbox`, `POST /v1/messages/delivered`, `POST /v1/messages/read` | 아직 읽지 않은 메시지. 가져오면 `delivered`, **결과를 모델에 돌려준 뒤에만 `read`** |
| `nexus_tree` | `task_id` | `GET /v1/tasks[/{id}]` | 이 세션이 볼 수 있는 작업 트리 |
| `nexus_log` | `session`(ID 또는 동료 이름, 생략 시 자기), `after` | `GET /v1/sessions/{id}/events` | 원장 한 쪽 `{events, next}`. 세션 권한으로 보이는 것만 |

**옛 이름**: `hub_peers`·`hub_inbox`·`hub_tree`·`hub_log` 는 한 전환 기간 동안 `tools/call` 에서만 받는다(숨은 별칭, `tools/list` 에 없음, 원장 기록에는 `alias` 로 남김). 엔진은 `hub_*` 를 낸 적이 없어 엔진 쪽 개명은 없다.

**엔진의 기존 Nexus 도구와의 관계**: TUI 엔진(`internal/nexustools`, `--nexus-tools`)은 지금도 `nexus_send`·`nexus_peers`·`nexus_inbox`(공유 모델 큐, 읽음은 모델 제공자 수락 후 core 가 기록)·`nexus_tasks`·`nexus_delegate`·`nexus_execute` 등을 낸다. 같은 서버 경로·같은 "읽음" 기준을 쓰지만 이름·인자가 다른 것이 있다(`nexus_send`↔`send_message`, `nexus_delegate`↔`delegate_task`). 엔진을 이 계약 도구로 옮기는 것은 다음 단계다(아래 한계).

### 결과와 오류

- 성공: 도구 결과 텍스트 = JSON 값 하나(`isError:false`).
- 도구 오류: `isError:true`, 텍스트 = `{"error":코드,"message":고정 한국어}`. 코드: `not_live`(로그인 만료 → 사람이 `newtype` 실행), `refused`(위임 밖·한도 초과 — Nexus 403/429), `not_found`, `conflict`, `invalid`, `cancelled`, `unavailable`(결과 불명, 새 ID 로 재전송 금지), `no_approver`, `approval_unavailable`(elicitation 에 클라이언트가 답하지 않음 · 승인되지 않음 · 다른 경로로 넘어가지 않음). 서버 응답 본문이나 토큰은 오류에 들어가지 않는다.
- 엔진 경로: 같은 JSON 을 Go error 텍스트로 돌려준다.
- 프로토콜 오류(JSON-RPC): `-32700` 구문, `-32600` 잘못된 요청·배치·초과 크기, `-32601` 없는 메서드, `-32602` 잘못된 인자·**모르는 도구**, `-32002` 초기화 전.

### 적합성 시험 (엔진 경로 = MCP 경로)

`internal/nmcp/conformance_test.go` 가 같은 호출을 두 경로로 돌려 같은 결과를 확인한다(가짜 Gate/Nexus: 실제 `nexus.Service` + `httpapi`, TLS 루프백).

1. **위임 밖 행동은 거절**: `delegation_info{action:"tool:shell"}` → `deny`; 없는 범위의 `delegate_task` → `refused`; `request_approval` → 사람 자리로 `requested`(권한 아님); 이미 허용된 행동 → `allowed`.
2. **아래는 권한을 넓힐 수 없음**: `model_tokens`·`sub_sessions` 를 주거나 없는 범위를 주면 `refused`; `session:delegate` 를 넘겨도 자식 깊이는 Nexus 가 0 으로 깎는다; 자기 한도 안의 위임은 성공하고 `task_status` 로 보인다.
3. **읽음은 돌려준 때만**: peers·tree·log·delegation_info 는 영수증을 건드리지 않는다; `nexus_inbox` 로 돌려준 뒤에만 `delivered`+`read`; 한 번 돌려준 메시지는 다시 나오지 않는다. MCP 경로는 응답을 실제로 쓴 뒤에 기록한다(`server_test.go` 가 응답을 읽기 전엔 `read` 가 없음을 확인).

## 4. stdio MCP 서버 (1단계) — `newtype nmcp serve --name NAME`

- JSON-RPC 2.0, 한 줄에 메시지 하나(stdin/stdout). `initialize`(요청 버전이 `2026-07-28`·`2025-11-25`·`2025-06-18`·`2025-03-26`·`2024-11-05` 중이면 그대로, 아니면 `2026-07-28`), `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `notifications/cancelled`(취소된 호출은 응답·읽음 기록 없음), `resources/list|templates/list|read|subscribe|unsubscribe`(아래 연동 가이드). stdin 이 끝나면 진행 중인 호출에 5초를 준 뒤 끝낸다.
- 시작하면 저장된 자격 증명(`~/.newtype/credentials` 또는 `--credential-dir`)으로 이름 `NAME` 의 로컬 Nexus 세션을 찾거나 만들고, **새 루트를 발급**한다(`POST /v1/requests`, 같은 세션이면 `to_session_id`): 범위 `session:delegate` 하나, 모델 토큰 0, `max_depth` 1, 8시간. 모델 범위가 없으므로 이 위임으로 모델을 부를 수 없다(외부 클라이언트는 자기 모델을 쓴다). 위임 내용은 지시문·도구 설명에 넣지 않고 `delegation_info` 로만 읽는다.
- **원장**: 메시지·위임·영수증은 원래대로 원장에 남는다. 여기에 더해 호출마다 `tool.call` 기록(도구 이름·결과 코드만, 인자·본문 없음)을 **그 세션 자신의 원장**에 쓴다 — 새 서버 경로 `POST /v1/sessions/{session}/events`(세션 자신만, `tool.*` 종류만, source `tool`, 한 번에 20건). 이 경로가 없는 옛 Nexus 는 404 를 주고, 서버는 stderr 에 한 번 알린 뒤 기록 없이 계속 동작한다.
- stdout 은 JSON-RPC 전용, stderr 는 고정 짧은 줄. 자격 증명은 어디에도 출력하지 않는다. 로그인이 살아 있지 않으면 "Nexus 로그인이 유효하지 않습니다 · newtype 을 실행해 로그인한 뒤 다시 하세요" 로 끝난다.
- 승인 요청을 받을 사람 자리: `--approver NAME`(기본 `operator` = `newtype nexus` 의 기본 자리). 그 자리가 한 번도 만들어지지 않았으면 `no_approver`.

### 2·3단계 (2026-10-04) — elicitation · Tasks · 실행 허가 읽기

- **elicitation**: `initialize` 의 클라이언트 `capabilities.elicitation` 이 있으면 `request_approval` 이 서버→클라이언트 요청 `elicitation/create`(`message`, `requestedSchema` = 선택지 `once`/`session`/`deny` 하나)를 보내고 응답(`accept`/`decline`/`cancel`)을 기다린다(최대 10분). 응답은 호스트(사람)가 하며 모델이 만들 수 없다. 서버 요청 ID 는 `"nmcp-N"`, 응답이 아닌 줄이나 모르는 ID 는 무시한다. 답이 없거나 오류면 `approval_unavailable` 이고 메시지 경로로 넘어가지 않는다.
- **Tasks 확장**(협상 버전 `2025-11-25` 이상): 서버가 `capabilities.tasks`(`list`, `cancel`, `requests.tools.call`)를 선언하고, `tools/list` 의 `task_status`·`nexus_inbox` 에 `execution.taskSupport:"optional"` 을 단다.
  - `tools/call` 에 `task:{ttl}` 를 붙이면 바로 `{task:{taskId,status:"working",createdAt,lastUpdatedAt,ttl,pollInterval}}` 를 돌려주고 호출은 뒤에서 돈다.
  - `tasks/get`, `tasks/list`, `tasks/cancel`, `tasks/result` 를 받는다. `tasks/result` 는 끝날 때까지 기다린 뒤 원래 `tools/call` 결과에 `_meta["io.modelcontextprotocol/related-task"]` 를 붙여 준다.
  - `nexus_inbox` 의 **`read` 영수증은 `tasks/result` 응답을 실제로 쓴 뒤 한 번만** 남는다. 취소된 작업은 결과도 영수증도 없다.
  - 다른 도구에 `task` 를 붙이거나 옛 버전 클라이언트가 붙이면 `-32602`, 옛 버전에서 `tasks/*` 는 `-32601`. 작업 핸들은 이 서버 프로세스 동안만 유지된다(재시작하면 사라짐).
- **실행 허가 읽기**: `delegation_info.execution_grants`(위 표). 발급·철회는 사람만(TUI/CLI, `docs/nmcp-delegated-execution.md`).
- 시험: `internal/nmcp/stages23_test.go` — elicitation 을 선언한 가짜 클라이언트와 선언하지 않은 클라이언트, Tasks 선언·옛 버전, 허가 목록과 `from` 거르기.

### Claude Code 설정

```
claude mcp add nexus -- "$HOME/.local/bin/newtype" nmcp serve --name claude-newtype
```

JSON 형식(`.mcp.json` 또는 `claude mcp add-json nexus '<JSON>'`):

```json
{"mcpServers":{"nexus":{"type":"stdio","command":"/absolute/path/to/newtype","args":["nmcp","serve","--name","claude-newtype"]}}}
```

Claude Code 에서 도구 이름은 `mcp__nexus__send_message` 처럼 보인다. 허용은 Claude Code 의 권한 규칙을 따른다.

### 클라이언트 연동 가이드 (2026-10-04) — 5분 폴링 · 구독 · Tasks · channel

`initialize` 결과의 `instructions`(한국어+영어)가 호스트에게 Nexus 가 무엇인지, 동기화 주기(할 일이 없으면 `nexus_inbox` 를 `wait_seconds` 최대 300 으로 부르고 반복), 메시지는 요청이지 권한이 아님, 읽음 = 모델에게 돌려준 것, 결과 보고(`send_message` 로 보낸 세션에, `reply_to` = 원래 `event_id`), `request_approval` 을 부를 때를 알려 준다. **읽음 영수증은 `nexus_inbox` 결과가 모델에게 넘어갈 때만** 남는다. 아래 어느 알림·구독·`resources/read` 도 `delivered`/`read` 를 남기지 않는다.

도구에는 MCP annotations 네 가지(`readOnlyHint`·`destructiveHint`·`idempotentHint`·`openWorldHint`)가 모두 붙는다(`nexusops.Hints`, 판정이 아니라 안내).

**레시피 1 — Claude Code channel(가장 쉬움: 쉬고 있는 세션이 메시지에 깨어난다).**

```bash
newtype nmcp setup claude --channel --apply
```

```bash
claude --dangerously-load-development-channels server:nexus
```

- `setup` 은 `claude` 가 있는지, 저장된 로그인이 살아 있는지 확인하고 `claude mcp add --scope user nexus -- <newtype 절대 경로> nmcp serve --name claude-newtype --channel` 을 보여 준다(`--apply` 면 실행). `--name`, `--scope user|project|local`, `--credential-dir` 를 받는다. 자격 증명은 출력하지 않는다(MCP 항목에는 실행 파일 경로와 플래그만 들어가고 서버가 시작할 때 저장된 자격 증명을 스스로 읽는다). 이미 같은 `nexus` 항목이 있으면 그렇다고만 하고, 다른 인자로 있으면 건드리지 않고 `claude mcp remove`/`add` 줄을 알려 준다. 기존 항목 확인에 `claude mcp get nexus` 를 쓰는데, Claude Code 가 이때 서버를 한 번 띄워 연결을 확인하므로 Nexus 에 루트가 한 번 더 발급될 수 있다.
- 미리보기 조건: Claude Code channels 는 연구 미리보기다. claude.ai 계정 또는 Console API 키 인증이 필요하고(서드파티 클라우드 제공자 인증으로는 불가), Team/Enterprise 조직은 관리자가 channels(`channelsEnabled`)를 켜야 한다. 직접 만든 channel 은 허용 목록에 없어 개발 플래그로 시작하며, 처음에 경고 대화상자에서 "I am using this for local development" 를 고른다.
- 사람이 보는 것: 시작 배너 아래 "Channels (experimental) messages from server:nexus inject directly in this session" 안내. 메시지가 오면 `← nexus: Nexus 에 새 메시지 1건 · nexus_inbox 로 읽으세요…` 한 줄이 보이고 Claude 가 스스로 `nexus_inbox` 를 불러 읽고 처리한다.
- 시험: 다른 터미널에서 `newtype nexus send --to claude-newtype "안녕, 테스트야"` → 쉬고 있던 Claude 세션이 깨어난다. `newtype nexus log claude-newtype` 에 `message.delivered`/`message.read` 가 `nexus_inbox` 뒤에만 생긴다.
- 동작: 서버가 `capabilities.experimental["claude/channel"]` 을 선언하고(`--channel` 을 줄 때만, 감시자가 있을 때만) 새 읽지 않은 메시지가 생기면 `notifications/claude/channel {content, meta:{unread, latest_event}}` 를 보낸다. Claude Code 는 세션이 열려 있는 동안 이것을 `<channel source="nexus" …>` 로 넣고 턴을 시작한다(세션이 닫혀 있으면 사라지고, 확인 응답은 없다). 알림 본문은 고정 문구라 **메시지 본문·보낸 이 제목을 넣지 않는다** — 다른 세션의 텍스트가 알림으로 모델에 들어가면 영수증 없는 읽음이 되기 때문이다. channel 이 켜지면 `instructions` 에 "알림이 오면 지금 nexus_inbox 를 부른다. 알림 자체에는 내용이 없다" 한 줄이 붙는다. 서버 시작 때 이미 읽지 않은 메시지가 있으면 한 번 알린다. 권한 중계(`claude/channel/permission`)는 선언하지 않는다(승인은 `request_approval` 경로로만).

**레시피 2 — 5분 폴링(모든 MCP 클라이언트).** 별도 설정 없음. 모델이 지시문대로 한가할 때 `nexus_inbox {"wait_seconds":300}` 을 부르고, 메시지가 오면 처리·회신한 뒤 다시 부른다. 300초 안에 오면 바로 돌아온다. 사람 없이 오래 돌릴 때는 호스트의 반복 기능(예: Claude Code `/loop 5m 'nexus_inbox 를 wait_seconds 300 으로 확인하고 온 요청을 처리해'`)을 쓴다.

**레시피 3 — 구독(SSE 를 서버가 대신 듣는다).** 서버는 `capabilities.resources {subscribe:true}` 를 선언한다.
- `resources/list` → `nexus://inbox`(읽지 않은 수와 `event_id` 만, 본문 없음). `resources/templates/list` → `nexus://tasks/{task_id}`(기다림 없는 `task_status`, 원장 기록 없음).
- `resources/subscribe {"uri":"nexus://inbox"}` 하면 서버가 자기 세션의 Nexus 스트림(`GET /v1/sessions/{id}/stream`, `Last-Event-ID` 커서, 스트림 수명이 끝나면 다시 연다)을 열고, 읽지 않은 메시지가 새로 생길 때 `notifications/resources/updated {"uri":"nexus://inbox"}` 를 보낸다. 작업 URI 는 상태가 바뀔 때 보낸다. 스트림 경로가 없는 Nexus(404/405)면 30초 폴링으로 바꾼다.
- 알림을 받으면 클라이언트는 `nexus_inbox` 를 부른다(그때 비로소 읽음).
- 일반 MCP 클라이언트 설정 예(stdio):

```json
{"mcpServers":{"nexus":{"command":"newtype","args":["nmcp","serve","--name","my-agent"]}}}
```

  Claude Code 는 구독 알림으로 유휴 세션에 턴을 열지 않는다(문서상 리소스 갱신은 목록 갱신에만 쓰인다). Claude Code 에서 깨우기가 필요하면 레시피 1.

**레시피 4 — Tasks(협상 버전 2025-11-25 이상).** `tools/call {"name":"nexus_inbox","arguments":{"wait_seconds":300},"task":{"ttl":600000}}` → 바로 작업 핸들. 다른 일을 하다가 `tasks/result` 로 받는다(그 응답을 쓴 뒤에 읽음). `task_status` 도 같은 방식. 핸들은 서버 프로세스 동안만 산다.

**원격 엔드포인트(설치 없음, 5단계).** Nexus 가 `https://<nexus-origin>/mcp` 를 직접 연다(Streamable HTTP, OAuth 2.1, 같은 계약). 호스팅 서비스의 예:

```bash
claude mcp add --transport http nexus https://lic.newtype-ai.com/mcp
```

  Claude Code 가 브라우저로 Nexus 동의 페이지를 열고, 페이지의 코드로 `newtype nmcp authorize CODE` 를 실행하면(메일 동의를 켰다면 owner 는 확인 메일의 링크로도) 연결된다. 연결 목록·끊기: `newtype nmcp clients`, `newtype nmcp revoke ID|이름`. 확인 메일 버튼(기본 꺼짐)은 owner 가 `newtype nmcp mail-consent on|off` 또는 TUI 의 `/nmcp mail-consent`·대화로 켜고 끈다. `authorize` 는 먼저 클라이언트·돌아갈 곳·요청 IP 를 보여 주고 y/N 을 묻는다. 원격에서는 channel 이 없으므로 깨우기는 레시피 2–4. 설계·구현: `docs/nmcp-remote-endpoint.md`.

**자체 호스팅 Nexus.** MCP 서버는 저장된 자격 증명의 엔드포인트(origin)로 붙는다. 자체 호스팅 Nexus 를 쓰려면 그 origin 으로 가입·로그인한 자격 증명을 별도 디렉터리에 두고 `--credential-dir DIR` 을 준다. 도구 계약과 시험(`internal/nmcp`, `conformance`)은 특정 Nexus 에 묶이지 않는다.

시험: `internal/nmcp/sync_test.go` — 지시문 내용, 모든 도구의 annotations, 구독 → 가짜 Nexus 에 메시지 → `notifications/resources/updated`(본문 없음, `delivered`/`read` 없음) → `resources/read` 도 영수증 없음 → `nexus_inbox` 뒤에만 읽음, `--channel` 알림도 영수증 없음·channel 지시문 줄, 잘못된 리소스 URI 거절. 클라이언트 쪽 `nmcp_setup_test.go`(클라이언트 저장소) — setup 출력(channel 유무), `--apply`·이미 있음·다른 인자, `claude` 없음·자격 증명 없음 거절, 출력에 비밀 없음, `--help`.

### 끝에서 끝까지 시험 (Claude ↔ newtype)

1. 터미널 A: `newtype --nexus-chat` (또는 `newtype nexus chat on` 뒤 `newtype`) → TUI 에서 `/name nmcp`.
2. 터미널 B: `newtype nexus inbox` 한 번(승인 요청을 받을 `operator` 자리 생성), `newtype nexus peers` 로 `nmcp` 확인.
3. Claude Code 세션(위 설정): "nexus_peers 로 동료를 보고, nmcp 에게 send_message 로 인사한 뒤 nexus_inbox 를 wait_seconds 120 으로 기다려" 라고 시킨다.
4. TUI 에 메시지가 들어오고 자동 수신 턴이 열린다. 답장 `nexus_send` 승인창에서 사람이 승인한다.
5. Claude 의 `nexus_inbox` 가 답을 돌려준다. 확인: `newtype nexus log nmcp`(TUI 원장: 받은 메시지, `message.delivered`/`message.read`, 보낸 답), `newtype nexus log claude-newtype`(Claude 세션 원장: `message.sent`, 영수증, `tool.call`).
6. 위임 밖 시험: Claude 에게 `delegate_task` 를 `scope:["newtype:run"]` 으로 시키면 `refused`, `request_approval` 은 `operator` 자리로 요청을 보낸다(`newtype nexus inbox` 로 보임).

### 1단계 완료 기준 대비 남은 것

- 도구 호출 원장 기록(`tool.call`)은 `POST /v1/sessions/{session}/events` 가 있는 Nexus 에만 남는다. 옛 Nexus 에는 메시지·위임·영수증만 남는다.
- `request_approval`: elicitation 을 선언한 클라이언트는 사람이 바로 결정하고(한 번만/이 세션 동안, 원장 `tool.approval`), 그 밖에는 운영자 자리로 가는 **메시지**다. **메일 승인 경로는 아직 없다**: 메일 승인은 승인 서버의 관리 토큰이 필요한데 세션(MCP 서버 프로세스)은 그것을 갖지 않는다. 사람이 없을 때 메일로 묻는 것은 서버 쪽(Nexus) 기능으로 따로 만든다. 어느 경로의 승인도 Nexus 위임을 넓히지 않는다.
- `--no-reply` 표시는 본문 접두어 규약이다(서버 필드 없음).
- 루트는 8시간이다. 서버 실행 중에 만료되면 호출이 `refused` 가 되고, 다시 시작하면 새 루트를 받는다(자동 갱신 없음).
- 엔진(TUI)은 아직 기존 `nexus_*` 도구 이름을 쓴다. 계약 도구 세트로 옮기는 일과 `/load` 시 제목 맞추기가 남았다.
- 2단계(받는 길): 기다리는 `nexus_inbox` 와 Tasks 확장(작업 핸들)이 있다. 새 메시지 알림은 `nexus://inbox` 구독과 Claude Code channel(`--channel`)로 있다(위 연동 가이드). 실행 허가를 묻는 호스트 훅(PreToolUse)은 아직이다.
