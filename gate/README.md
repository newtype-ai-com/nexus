# Gate 구현 현황

현재 `gate`는 **감사 로그·Nexus 인증·Postgres 자격/계정/등록 저장소·메일 승인 기반 발급·검증·철회**를 제공한다. `cmd/nexus`에 연결되며 모델 중계와 설치 패키지는 아직 없다. 실행·배포 절차는 [self-host 안내](../docs/selfhost.md)를 따른다.

## 등록·발급 수직 기능 (2026-10-02)

- `POST /v1/enrol {email}` → 허용 목록 검증 → private Resend 메일 → `GET /enrol/verify?t=…` 확인 페이지 → **POST 승인**. 메일 스캐너 GET/HEAD는 승인하지 않는다.
- `GET /v1/enrol/{id}`와 `/key`, `/session`은 poll Bearer 필요. 키와 로그인은 각각 한 번만 수령하며 재요청은 410, HEAD는 405. 응답 유실 시 재발급 대신 등록부터 다시 한다.
- `gate_accounts`의 email 유일성 및 트랜잭션 잠금으로 같은 주소의 계정을 유지한다. 기존 수동 provision 계정을 채택하고, 여러 계정으로 갈린 주소는 자동 병합하지 않고 충돌로 차단한다.
- CSPRNG 32바이트 토큰(`ntl_`, `ntg_`, `enp_`, `vfy_`)은 DB에 SHA-256만 저장. 등록 30분, 승인 시점부터 로그인 30일·라이선스 365일 절대 만료. 주소별 살아 있는 등록은 3개까지다.
- `POST /v1/validate`: licence + `X-Newtype-Login` 동일 계정 확인, 최대 35초 lease(자격 만료보다 길지 않음). 클라이언트 heartbeat 강제 연결은 별도다.
- `POST /v1/admin/revoke {verifier}`: 명시 ADMIN Bearer만 허용. 프록시 loopback은 운영자로 취급하지 않는다. 메모리/DB 모두 신원 변경 및 철회 되돌림 금지.
- 설정 전체가 없으면 등록은 비활성. 일부만 설정하면 시작 실패. `BASE_URL` HTTPS, `ENROL_ALLOW`, `RESEND_API_KEY`, `MAIL_FROM` 모두 필요, `ADMIN_TOKEN` 선택. 메일 오류/본문/링크는 오류 문자열에 싣지 않는다.
- PostgreSQL 통합: 두 pool·handler 재생성, 동시 20회 수령 중 1회 성공, 같은 주소 계정 유지, 만료·철회, 평문 미저장, 메일 실패·요청 제한 테스트 통과. 실제 Resend 발송/클라우드 배포는 하지 않았다.

**남은 범위:** RFC 8628 device 재로그인, 서명된 로그인 인증서·패스키, 동적 allowlist 관리, 감사 handler 배선, 만료 등록 보관·청소 정책, 배포 단위 global/IP rate limit. 현재 재로그인은 새 등록/메일 승인으로 가능하나 기존 라이선스를 재사용하는 device flow가 아니다. CLI 자동 credential 저장·설치 흐름과 모델 게이트웨이는 미구현이다.

## Nexus 인증 어댑터

- `NexusAuth.Authenticate`를 `httpapi.Config.Authenticate`에 주입할 수 있다. `CredentialStore`는 신뢰된 등록 경로에서 생성한 SHA-256 verifier·계정·종류·기한·철회 상태를 보관한다. 현재 `MemoryCredentials`와 서버 전용 `PostgresCredentials`를 제공한다. 후자는 신원 불변·sticky revocation·별도 schema version 1을 적용한다.
- 로컬 접속은 Bearer licence + `X-Newtype-Login`의 동일 계정 결합을 요구한다. `X-Newtype-Session`을 지정하면 그 계정의 local 세션으로만 바인딩한다.
- `nta_` agent bearer는 저장된 container 세션 및 유효한 위임 계보에 결속된다. 로그인/세션 헤더로 다른 주체를 선택할 수 없다.
- 중복 Authorization, 잘못된 종류·계정·기한·철회를 거부한다. 인증 테스트는 합성 자격증명이며 실제 로그인/등록/메일/키 회전의 검증이 아니다.
- 운영에서는 영구 자격증명 저장소, 안전한 발급·회전·철회, TLS 서버 조립이 별도로 필요하다.

## 감사 로그

```go
audit, err := gate.NewAudit(os.Stdout)
// err 확인 후 서버 수명 동안 공유한다.
// 인증에서 확정한 값만 Established에, 호출자 메타데이터는 Asserted에 넣는다.
audit.Write(gate.AuditEvent{Type: "validate"})
// health 응답의 audit_dropped = audit.Dropped()
// HTTP 요청 처리를 중단하고 배출한 뒤 audit.Close() 오류를 확인한다.
```

- 큐 1,024개. 가득 차면 `Write`는 출력 I/O를 기다리지 않고 `false`를 반환하며 누적 손실을 센다.
- 출력은 단일 고루틴의 JSON lines. 10초마다 새 손실을 `audit_dropped` 사건으로 보고하고 종료 시에도 남은 손실을 보고한다. 출력이 막혀 있으면 보고도 지연될 수 있다.
- `Write`와 `Close`가 같은 잠금 아래 채널 전송/종료를 처리한다. 중복·동시 `Close`는 안전하며 수락된 사건을 배출한다. 종료 뒤 호출은 거절하고 손실 수에는 넣지 않는다.
- `Close`는 출력 완료를 기다린다. 영원히 멈출 수 있는 writer를 연결하지 않는다. 전달한 writer 자체를 닫지는 않는다.
- 출력 실패·short write도 누락으로 집계하고 `Close`가 일반화된 `ErrAuditOutput`을 반환한다. 실패한 drop 보고는 다음 보고에서 재시도한다. 출력 저장소 장애 중 로그 영속성은 보장하지 않는다.
- 사건에는 임의 payload/프롬프트/자격증명 필드가 없다. 알려진 토큰은 `redact.JSON`으로 가리되, 임의 비밀 검출을 보장하지 않으므로 호출자가 비밀값·승인 링크·요청 본문을 넣어서는 안 된다.
- `Established`/`Asserted`의 구분은 데이터 계약이지 인증 구현이 아니다. 향후 핸들러가 요청 JSON을 `Established`로 복사해서는 안 된다.

## 검증

Go 1.24에서 `go test -race -count=10 ./gate`, `go vet ./gate`, `CGO_ENABLED=0 go build ./gate` 및 gofmt 검사를 통과했다. 네트워크 없는 Docker에서 실행했으며 실제 DB·메일·모델을 사용하지 않았다.

회귀 테스트: 동시 Write/Close, 종료 시 큐 배출·누락 보고, 막힌 writer에서 큐 초과 비차단, drop 보고 차분·실패 재시도, 출력 오류·short write, 토큰 가리기, 2^53보다 큰 사용량 보존, 확정/주장 주체 분리.
