package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/mcpauth"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

// Pipe-only secret input for `nexus migrate` (pre-Nexus bootstrap §3-3, Q2,
// BBOOT2 answer 4). Two exclusive forms, both reading one anonymous pipe FD
// supplied by the direct-binary supervisor (bounded to dsnFDLimit bytes, EOF
// required within dsnFDTimeout, FD closed on every path):
//
//	nexus migrate --db-password-fd N   (bootstrap form, fd 30)
//	    FD: {"version":1,"dbPassword":"…"} — the same db-admin payload the
//	    grants executor reads. The DSN is the PUBLIC template in
//	    NEXUS_MIGRATE_DSN, which must not contain a password; the password is
//	    put into the pgx config struct, never into a DSN string.
//	nexus migrate --dsn-fd N
//	    FD: the whole DSN (password included), optional trailing newline.
//
// There is exactly one secret source: DATABASE_URL, NEXUS_DB_DSN and every PG*
// driver variable (PGPASSWORD, PGPASSFILE, PGSERVICE, PGSERVICEFILE, PGSSL*,
// …) must be absent; passfile/service/servicefile/ssl key options are refused
// in the DSN; and the parsed config must take its password only from the FD
// (no passfile default). Non-secret settings come from the environment
// allowlist below; nothing else (tokens, sealing keys, mail) is read. No
// DATABASE_URL is set and no process is spawned. verify-full/CA/port/schema/
// role checks are those of nexusserver.ConfigFromEnv; NEXUS_DB_ROLE (the SET
// ROLE identity, e.g. nexus_migrator) is required, the session user is the
// DSN user. Authentication is SCRAM-SHA-256 only (pgstore.Config.RequireSCRAM).
// Errors are fixed strings.
const (
	dsnFDLimit   = 4096
	dsnFDTimeout = 10 * time.Second
)

// migrateFDBudget bounds the whole pipe-mode run after the FD is read
// (design §3-6 migrator 120 s; below the orchestrator's 240 s consumer budget).
// Per-statement/lock bounds come from NEXUS_DB_STATEMENT_TIMEOUT_MS /
// NEXUS_DB_LOCK_TIMEOUT_MS in the consumer manifest.
var migrateFDBudget = 120 * time.Second

var errDSNFD = errors.New("nexus: migrate pipe input refused")

// migrationsComplete is the whole success stdout of `nexus migrate` (one line,
// nothing else on stdout). In pipe mode it is printed only after the in-process
// readback (hub_meta schema = pgstore.SchemaVersion, gate credentials =
// gate.CredentialSchemaVersion, enrolments checked) succeeded; every failure
// prints nothing on stdout and exits 1 with a fixed stage error on stderr. The
// bootstrap's exact response predicate for P5a (bootstrap_raw OUTPUTS
// 'schema9-migrate') matches these bytes; it must not accept any zero exit.
const migrationsComplete = "Nexus and Gate migrations complete"

// publicMigrateSettings are the only environment keys read in this mode.
var publicMigrateSettings = map[string]bool{
	"NEXUS_DB_SCHEMA":               true,
	"NEXUS_DB_ROLE":                 true,
	"NEXUS_DB_STATEMENT_TIMEOUT_MS": true,
	"NEXUS_DB_LOCK_TIMEOUT_MS":      true,
	"NEXUS_ALLOW_LOCAL_DB":          true,
	"NEXUS_MIGRATE_DSN":             true,
}

const (
	fdModeDSN      = "--dsn-fd"
	fdModePassword = "--db-password-fd"
)

var errFDUsage = errors.New("usage: nexus migrate --db-password-fd N | --dsn-fd N")

// parseDSNFDArgs accepts exactly ["migrate", --db-password-fd|--dsn-fd, N], N >= 3.
func parseDSNFDArgs(args []string) (string, int, error) {
	if len(args) != 3 || args[0] != "migrate" || (args[1] != fdModeDSN && args[1] != fdModePassword) {
		return "", 0, errFDUsage
	}
	fd, err := strconv.Atoi(args[2])
	if err != nil || fd < 3 || fd > 1<<20 || strconv.Itoa(fd) != args[2] {
		return "", 0, errFDUsage
	}
	return args[1], fd, nil
}

// migrateEnvironment refuses ambient database settings and returns a getter
// restricted to the public allowlist.
func migrateEnvironment(environ []string) (func(string) string, error) {
	values := map[string]string{}
	for _, kv := range environ {
		key, value, _ := strings.Cut(kv, "=")
		if key == "DATABASE_URL" || key == "NEXUS_DB_DSN" || strings.HasPrefix(key, "PG") {
			return nil, errors.New("nexus: migrate pipe mode refuses ambient database settings")
		}
		if publicMigrateSettings[key] {
			values[key] = value
		}
	}
	return func(k string) string { return values[k] }, nil
}

// checkURL applies the rules shared by both forms; withPassword says whether
// the DSN itself carries the (non-empty) password.
func checkURL(dsn string, withPassword bool) error {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.User.Username() == "" {
		return errDSNFD
	}
	password, ok := u.User.Password()
	if withPassword != (ok && password != "") || (!withPassword && ok) {
		return errDSNFD
	}
	query := u.Query()
	for _, key := range []string{"password", "passfile", "service", "servicefile", "sslpassword", "sslkey", "sslcert"} {
		if _, present := query[key]; present {
			return errDSNFD
		}
	}
	pc, err := pgxpool.ParseConfig(dsn)
	// the parsed password must be exactly the DSN's own: never a passfile default
	if err != nil || pc.ConnConfig.Password != password || len(pc.ConnConfig.Fallbacks) != 0 {
		return errDSNFD
	}
	return nil
}

// checkPasswordPayload decodes {"version":1,"dbPassword":"…"} exactly (the
// runner's db_password schema: 8–512 bytes, no control characters).
func checkPasswordPayload(raw []byte) (string, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var p struct {
		Version    *int    `json:"version"`
		DBPassword *string `json:"dbPassword"`
	}
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version == nil || *p.Version != 1 || p.DBPassword == nil {
		return "", errDSNFD
	}
	// duplicate keys are refused (encoding/json keeps the last one silently)
	t := json.NewDecoder(bytes.NewReader(raw))
	seen := map[string]bool{}
	if tok, err := t.Token(); err != nil || tok != json.Delim('{') {
		return "", errDSNFD
	}
	for t.More() {
		tok, err := t.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey || seen[key] {
			return "", errDSNFD
		}
		seen[key] = true
		var skip json.RawMessage
		if t.Decode(&skip) != nil {
			return "", errDSNFD
		}
	}
	pw := *p.DBPassword
	if len(pw) < 8 || len(pw) > 512 || !utf8.ValidString(pw) {
		return "", errDSNFD
	}
	for _, c := range []byte(pw) {
		if c < 0x20 || c == 0x7f {
			return "", errDSNFD
		}
	}
	return pw, nil
}

// checkDSN applies the single-source rules to --dsn-fd contents.
func checkDSN(raw []byte) (string, error) {
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return "", errDSNFD
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", errDSNFD
		}
	}
	dsn := string(raw)
	if checkURL(dsn, true) != nil {
		return "", errDSNFD
	}
	return dsn, nil
}

// migrateSteps runs the existing migration sequence; the failing stage is the
// only detail reported.
func migrateSteps(ctx context.Context, store *pgstore.Store, credentials *gate.PostgresCredentials, schema string) error {
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"ensure schema", func() error { return store.EnsureSchema(ctx, schema) }},
		{"nexus", func() error { return store.Migrate(ctx) }},
		{"credentials", func() error { return credentials.Migrate(ctx) }},
		{"enrolments", func() error { return credentials.MigrateEnrolments(ctx) }},
		{"mcp oauth", func() error { return mcpauth.NewPostgresStore(store.Pool()).Migrate(ctx) }},
		{"secure schema", func() error { return nexusserver.SecureSchema(ctx, store.Pool(), schema) }},
	} {
		if step.run() != nil {
			// Identify the stage, never expose raw SQL errors or credentials.
			return fmt.Errorf("nexus: migration failed (%s)", step.name)
		}
	}
	return nil
}

// runMigrateDSNFD is the whole --dsn-fd mode. readFD is the bounded pipe
// reader (readDSNFD in production).
func runMigrateDSNFD(ctx context.Context, args []string, environ []string, readFD func(int) ([]byte, error)) (err error) {
	mode, fd, err := parseDSNFDArgs(args)
	if err != nil {
		return err
	}
	get, err := migrateEnvironment(environ)
	if err != nil {
		return err
	}
	template := get("NEXUS_MIGRATE_DSN")
	if (mode == fdModePassword) != (template != "") {
		return errors.New("nexus: migrate pipe mode requires exactly one DSN source")
	}
	if mode == fdModePassword && checkURL(template, false) != nil {
		return errors.New("nexus: invalid NEXUS_MIGRATE_DSN")
	}
	raw, err := readFD(fd)
	defer clear(raw)
	if err != nil {
		return err
	}
	var dsn, password string
	if mode == fdModePassword {
		dsn = template
		password, err = checkPasswordPayload(raw)
	} else {
		dsn, err = checkDSN(raw)
	}
	if err != nil {
		return err
	}
	cfg, err := nexusserver.ConfigFromEnv(func(k string) string {
		if k == "DATABASE_URL" {
			return dsn
		}
		return get(k)
	})
	if err != nil {
		// ConfigFromEnv errors are fixed strings; none echoes the DSN.
		return err
	}
	if cfg.DBRole == "" {
		return errors.New("nexus: migrate pipe mode requires NEXUS_DB_ROLE")
	}
	ctx, cancel := context.WithTimeout(ctx, migrateFDBudget)
	defer cancel()
	store, err := pgstore.Open(ctx, pgstore.Config{
		DSN: cfg.DSN, Password: password, Schema: cfg.Schema, MaxConns: 8, RequireSCRAM: true,
		Role: cfg.DBRole, StatementTimeoutMS: cfg.DBStatementTimeoutMS, LockTimeoutMS: cfg.DBLockTimeoutMS,
	})
	if err != nil {
		return fmt.Errorf("nexus: database connection failed (%s)", pgstore.ConnectionStage(err))
	}
	defer store.Close()
	credentials := gate.NewPostgresCredentials(store.Pool())
	if err := migrateSteps(ctx, store, credentials, cfg.Schema); err != nil {
		return err
	}
	// Read back the versions the serve check requires (stage "verify").
	var nv, gv int
	if store.Pool().QueryRow(ctx, `SELECT value FROM hub_meta WHERE key='schema'`).Scan(&nv) != nil || nv != pgstore.SchemaVersion ||
		store.Pool().QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='credentials'`).Scan(&gv) != nil || gv != gate.CredentialSchemaVersion ||
		credentials.CheckEnrolments(ctx) != nil {
		return errors.New("nexus: migration failed (verify)")
	}
	var mv int
	if store.Pool().QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='mcp_oauth'`).Scan(&mv) != nil || mv != mcpauth.SchemaVersion {
		return errors.New("nexus: migration failed (verify mcp oauth)")
	}
	fmt.Println(migrationsComplete)
	return nil
}
