# gate

Package `gate` holds everything in Nexus that decides who may act: credential
issuance and validation, enrolment, owner and user admission, quotas, the model
gateway and the audit log. `internal/nexusserver` assembles these handlers into
the `nexus serve` process; deployment is described in
[docs/selfhost.md](../docs/selfhost.md).

## Main parts

- **Credentials.** `CredentialStore` keeps SHA-256 verifiers only, never the
  token. `NewMemoryCredentials` is for tests; `NewPostgresCredentials` is the
  server store (immutable identity, sticky revocation). `NexusAuth` adapts a
  store into the authenticator used by `nexus/httpapi`. `ValidateHandler`
  serves `POST /v1/validate`.
- **Enrolment.** `NewEnrolmentHandler` serves `POST /v1/enrol`, mail
  verification (`/enrol/verify`, approved only by POST), one-time key and
  session claims, the operator's owner code (`POST /v1/enrol/code`, only when
  `NEXUS_OWNER_CODE=1`) and `POST /v1/admin/revoke` (requires `ADMIN_TOKEN`).
  `NewDeviceHandler` serves device re-login. Mail goes through
  `NewResendMailer`.
- **Owner and users.** `NewOwnerCredentialsWithPolicy` ties owner features to
  `NEXUS_OWNER_EMAIL`; `NewUserAdmissionHandler` and `NewQuotaHandler` handle
  mailed approval of new users and token-quota increases.
- **Change approvals.** `NewChangeHandler`, `NewChangeAdminClient` and
  `NewDefaultModelOperator` implement owner-approved operator changes such as
  the default model (`nexus approvals`).
- **Model gateway.** `NewModelHandler` relays model calls to one configured
  upstream with per-session ceilings, retries and a call budget;
  `NewModelAccessHandler` exposes the allowed models.
- **Audit.** `NewAudit` writes JSON lines from a bounded queue. A full queue
  drops instead of blocking and reports the count as `audit_dropped`. Events
  carry no payloads or credentials, and known tokens are redacted.

## Testing

Unit tests use in-memory stores, a fake mailer and synthetic credentials, and
need no network:

```sh
go test ./gate
```

Tests that need PostgreSQL run when `NTS_NEXUS_TEST_DSN` points at a disposable
database and are skipped otherwise.
