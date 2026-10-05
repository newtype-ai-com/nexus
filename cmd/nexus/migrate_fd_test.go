//go:build linux || darwin

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
	"golang.org/x/sys/unix"
)

// schema6SQL is nexus/pgstore/schema.sql at 1e72501 (SchemaVersion 6), the
// version the production database reports (design §9-1).
//
//go:embed testdata/schema6.sql
var schema6SQL string

const fdSentinel = "public-sentinel-dsn-fd-pw"

// pipeFD returns the read end of an anonymous pipe holding data; the write
// end is closed unless keepOpen.
func pipeFD(t *testing.T, data []byte, keepOpen bool) int {
	t.Helper()
	p := make([]int, 2)
	if err := unix.Pipe(p); err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 {
		if _, err := unix.Write(p[1], data); err != nil {
			t.Fatal(err)
		}
	}
	if keepOpen {
		t.Cleanup(func() { unix.Close(p[1]) })
	} else {
		unix.Close(p[1])
	}
	return p[0]
}

func closed(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == unix.EBADF
}

func TestDSNFDArguments(t *testing.T) {
	for _, args := range [][]string{
		{"migrate", "--dsn-fd"}, {"migrate", "--dsn-fd", "2"}, {"migrate", "--dsn-fd", "x"}, {"migrate", "--dsn-fd", "03"},
		{"migrate", "--dsn-fd=5"}, {"migrate", "--dsn", "5"}, {"migrate", "--dsn-fd", "5", "extra"},
	} {
		if _, _, err := parseDSNFDArgs(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	for _, mode := range []string{"--dsn-fd", "--db-password-fd"} {
		if m, fd, err := parseDSNFDArgs([]string{"migrate", mode, "30"}); err != nil || fd != 30 || m != mode {
			t.Fatal(fd, err)
		}
	}
	// Other modes never accept the flag, and fail before reading any FD/env.
	for _, args := range [][]string{{"serve", "--dsn-fd", "3"}, {"provision", "--dsn-fd", "3"}, {"approvals", "--dsn-fd", "3"}, {"--dsn-fd", "3"}} {
		if err := run(context.Background(), args, strings.NewReader("")); err == nil || !strings.HasPrefix(err.Error(), "usage: nexus [") {
			t.Fatalf("%q: %v", args, err)
		}
	}
	// run routes migrate --dsn-fd to the pipe mode.
	if err := run(context.Background(), []string{"migrate", "--dsn-fd", "nope"}, strings.NewReader("")); err == nil || err != errFDUsage {
		t.Fatal(err)
	}
}

func TestDSNFDSingleSource(t *testing.T) {
	for _, env := range [][]string{
		{"DATABASE_URL=postgres://x"}, {"DATABASE_URL="}, {"PGPASSWORD=x"}, {"PGPASSFILE=/tmp/p"}, {"PGSERVICE=s"},
		{"PGSERVICEFILE=/tmp/s"}, {"PGSSLROOTCERT=/x"}, {"PGHOST=h"}, {"NEXUS_DB_DSN=x"},
	} {
		called := false
		err := runMigrateDSNFD(context.Background(), []string{"migrate", "--dsn-fd", "9"}, env, func(int) ([]byte, error) { called = true; return nil, nil })
		if err == nil || err.Error() != "nexus: migrate pipe mode refuses ambient database settings" || called {
			t.Fatalf("%q: %v called=%t", env, err, called)
		}
	}
	get, err := migrateEnvironment([]string{"NEXUS_DB_SCHEMA=s", "ADMIN_TOKEN=secret", "RESEND_API_KEY=k", "NEXUS_DB_ROLE=r"})
	if err != nil || get("NEXUS_DB_SCHEMA") != "s" || get("NEXUS_DB_ROLE") != "r" || get("ADMIN_TOKEN") != "" || get("RESEND_API_KEY") != "" {
		t.Fatal("environment allowlist not applied")
	}
}

func TestDSNFDContents(t *testing.T) {
	// verify-full/CA/port are ConfigFromEnv's checks (TestDSNFDErrorsNeverEchoTheDSN)
	good := "postgres://nexus_migrator:" + fdSentinel + "@127.0.0.1:5432/postgres?sslmode=disable"
	if dsn, err := checkDSN([]byte(good + "\n")); err != nil || dsn != good {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", "\n", "postgres://nexus_migrator@db.example.test:5432/postgres?sslmode=verify-full",
		"postgres://nexus_migrator:@db.example.test:5432/postgres?sslmode=verify-full",
		good + "&passfile=/tmp/p", good + "&service=x", good + "&servicefile=/x", good + "&sslkey=/k",
		strings.Replace(good, "disable", "prefer", 1), good + "&sslrootcert=/nonexistent/ca.crt", "mysql://u:p@h/db", good + "\n\n", good + "\x00",
		"host=db user=u password=p sslmode=verify-full", string([]byte{0xff, 0xfe}),
	} {
		_, err := checkDSN([]byte(bad))
		if err == nil || err != errDSNFD {
			t.Fatalf("accepted %q: %v", bad, err)
		}
	}
}

func TestPasswordFDPayloadAndTemplate(t *testing.T) {
	good := `{"version":1,"dbPassword":"` + fdSentinel + `"}`
	if pw, err := checkPasswordPayload([]byte(good)); err != nil || pw != fdSentinel {
		t.Fatal(err)
	}
	if pw, err := checkPasswordPayload([]byte(`{"dbPassword":"a\"b\\c-0123456789abcd","version":1}`)); err != nil || pw != `a"b\c-0123456789abcd` {
		t.Fatal(pw, err)
	}
	// owner-approved bounds: 8..512 bytes (the production admin password is 11)
	for _, n := range []int{8, 11, 512} {
		pw := strings.Repeat("p", n)
		if got, err := checkPasswordPayload([]byte(`{"version":1,"dbPassword":"` + pw + `"}`)); err != nil || got != pw {
			t.Fatalf("refused %d-byte password: %v", n, err)
		}
	}
	for _, n := range []int{7, 513} {
		if _, err := checkPasswordPayload([]byte(`{"version":1,"dbPassword":"` + strings.Repeat("p", n) + `"}`)); err != errDSNFD {
			t.Fatalf("accepted %d-byte password", n)
		}
	}
	for _, bad := range []string{
		``, `{}`, `{"version":1}`, `{"dbPassword":"` + fdSentinel + `"}`, `{"version":2,"dbPassword":"` + fdSentinel + `"}`,
		`{"version":true,"dbPassword":"` + fdSentinel + `"}`, `{"version":1,"dbPassword":"short"}`,
		`{"version":1,"dbPassword":"` + fdSentinel + `","extra":1}`, `{"version":1,"dbPassword":"x","dbPassword":"` + fdSentinel + `"}`,
		`{"version":1,"dbPassword":"` + fdSentinel + `\n"}`, `{"version":1,"dbPassword":"` + fdSentinel + `"} {}`,
		`{"version":1,"dbPassword":"` + strings.Repeat("x", 513) + `"}`, "postgres://u:" + fdSentinel + "@h/db",
	} {
		if _, err := checkPasswordPayload([]byte(bad)); err != errDSNFD {
			t.Fatalf("accepted %q", bad)
		}
	}
	tmpl := "postgres://nexus_migrator@127.0.0.1:5432/postgres?sslmode=disable"
	if checkURL(tmpl, false) != nil {
		t.Fatal("template refused")
	}
	for _, bad := range []string{
		"postgres://nexus_migrator:" + fdSentinel + "@127.0.0.1:5432/postgres?sslmode=disable",
		"postgres://nexus_migrator:@127.0.0.1:5432/postgres?sslmode=disable",
		tmpl + "&password=x", tmpl + "&passfile=/p", "postgres://127.0.0.1:5432/postgres?sslmode=disable",
	} {
		if checkURL(bad, false) == nil {
			t.Fatalf("template accepted %q", bad)
		}
	}
	read := func(int) ([]byte, error) { return []byte(good), nil }
	// exactly one DSN source: the password form needs the public template,
	// the DSN form refuses it
	for _, c := range []struct {
		mode string
		env  []string
	}{
		{"--db-password-fd", []string{"NEXUS_DB_ROLE=r", "NEXUS_DB_SCHEMA=s"}},
		{"--dsn-fd", []string{"NEXUS_DB_ROLE=r", "NEXUS_DB_SCHEMA=s", "NEXUS_MIGRATE_DSN=" + tmpl}},
	} {
		err := runMigrateDSNFD(context.Background(), []string{"migrate", c.mode, "9"}, c.env, read)
		if err == nil || err.Error() != "nexus: migrate pipe mode requires exactly one DSN source" {
			t.Fatal(c.mode, err)
		}
	}
	err := runMigrateDSNFD(context.Background(), []string{"migrate", "--db-password-fd", "9"},
		[]string{"NEXUS_MIGRATE_DSN=postgres://u:" + fdSentinel + "@h:5432/db?sslmode=verify-full"}, read)
	if err == nil || err.Error() != "nexus: invalid NEXUS_MIGRATE_DSN" || strings.Contains(err.Error(), fdSentinel) {
		t.Fatal(err)
	}
}

func TestDSNFDReader(t *testing.T) {
	fd := pipeFD(t, []byte("postgres://u:p@h/db"), false)
	raw, err := readDSNFD(fd)
	if err != nil || string(raw) != "postgres://u:p@h/db" || !closed(fd) {
		t.Fatal(string(raw), err)
	}
	fd = pipeFD(t, []byte(strings.Repeat("x", dsnFDLimit+1)), false)
	if _, err := readDSNFD(fd); err != errDSNFD || !closed(fd) {
		t.Fatal("oversized input accepted", err)
	}
	// A regular file, a named FIFO and the write end of a pipe are refused.
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "dsn"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("postgres://u:p@h/db")
	regular, _ := unix.Dup(int(f.Fd()))
	f.Close()
	if _, err := readDSNFD(regular); err != errDSNFD {
		t.Fatal("regular file accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	named, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readDSNFD(named); err != errDSNFD {
		t.Fatal("named FIFO accepted")
	}
	p := make([]int, 2)
	if err := unix.Pipe(p); err != nil {
		t.Fatal(err)
	}
	unix.Close(p[0])
	if _, err := readDSNFD(p[1]); err != errDSNFD {
		t.Fatal("write end accepted")
	}
}

func TestDSNFDRequiresEOF(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 10 s EOF bound")
	}
	fd := pipeFD(t, []byte("postgres://u:p@h/db"), true)
	start := time.Now()
	_, err := readDSNFD(fd)
	if err != errDSNFD || time.Since(start) < dsnFDTimeout || time.Since(start) > dsnFDTimeout+3*time.Second || !closed(fd) {
		t.Fatal("missing EOF not bounded", err, time.Since(start))
	}
}

func TestDSNFDErrorsNeverEchoTheDSN(t *testing.T) {
	env := []string{"NEXUS_DB_SCHEMA=nexus_fixture", "NEXUS_DB_ROLE=nexus_migrator"}
	for _, dsn := range []string{
		"postgres://u:" + fdSentinel + "@db.example.test:6543/postgres?sslmode=verify-full",
		"postgres://u:" + fdSentinel + "@db.example.test:5432/postgres?sslmode=require",
		"postgres://u:" + fdSentinel + "@db.example.test:5432/postgres?sslmode=verify-full&host=other",
	} {
		err := runMigrateDSNFD(context.Background(), []string{"migrate", "--dsn-fd", "9"}, env, func(int) ([]byte, error) { return []byte(dsn), nil })
		if err == nil || strings.Contains(err.Error(), fdSentinel) || strings.Contains(err.Error(), "db.example.test") {
			t.Fatalf("%v", err)
		}
	}
	// a role is required: the session user is the login, SET ROLE the migrator
	err := runMigrateDSNFD(context.Background(), []string{"migrate", "--dsn-fd", "9"}, []string{"NEXUS_DB_SCHEMA=nexus_fixture", "NEXUS_ALLOW_LOCAL_DB=1"},
		func(int) ([]byte, error) { return []byte("postgres://u:p@127.0.0.1:1/postgres?sslmode=disable"), nil })
	if err == nil || err.Error() != "nexus: migrate pipe mode requires NEXUS_DB_ROLE" {
		t.Fatal(err)
	}
}

// --- disposable PostgreSQL (scram-sha-256 host auth) ---

func scramDSN(t *testing.T) string {
	dsn := os.Getenv("NTS_NEXUS_SCRAM_TEST_DSN")
	if dsn == "" {
		t.Skip("set NTS_NEXUS_SCRAM_TEST_DSN to a disposable loopback PostgreSQL with scram-sha-256 host auth (superuser, password in DSN)")
	}
	return dsn
}

func adminExec(t *testing.T, dsn, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

// schema6 builds a schema 6 database (Nexus schema 6 + Gate credentials 1 /
// enrolments 4) owned by a fresh NOLOGIN migrator role.
func schema6(t *testing.T, dsn string) (schema, role string) {
	t.Helper()
	id := strings.ToLower(string(ids.New(ids.KindEvent)))
	schema, role = "fd6_"+id, "fdmig_"+id
	adminExec(t, dsn, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN; CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()+" AUTHORIZATION "+pgx.Identifier{role}.Sanitize())
	t.Cleanup(func() {
		adminExec(t, dsn, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE; DROP OWNED BY "+pgx.Identifier{role}.Sanitize()+"; DROP ROLE "+pgx.Identifier{role}.Sanitize())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: schema, Role: role, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Pool().Exec(ctx, schema6SQL); err != nil {
		t.Fatal(err)
	}
	creds := gate.NewPostgresCredentials(s.Pool())
	if err := creds.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := creds.MigrateEnrolments(ctx); err != nil {
		t.Fatal(err)
	}
	if v := versions(t, dsn, schema); v != [3]int{6, 1, 4} {
		t.Fatalf("fixture is not schema 6: %v", v)
	}
	return schema, role
}

func versions(t *testing.T, dsn, schema string) [3]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	q := pgx.Identifier{schema}.Sanitize()
	var v [3]int
	if err := conn.QueryRow(ctx, "SELECT (SELECT value FROM "+q+".hub_meta WHERE key='schema'), (SELECT value FROM "+q+".gate_meta WHERE key='credentials'), (SELECT value FROM "+q+".gate_meta WHERE key='enrolments')").Scan(&v[0], &v[1], &v[2]); err != nil {
		t.Fatal(err)
	}
	return v
}

func relations(t *testing.T, dsn, schema string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, "SELECT c.relname, c.relkind::text || coalesce(':' || pg_get_indexdef(c.oid), '') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','i')", schema)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatal(err)
		}
		out[name] = def
	}
	return out
}

func fdEnv(schema, role string, extra ...string) []string {
	return append([]string{"NEXUS_DB_SCHEMA=" + schema, "NEXUS_DB_ROLE=" + role, "NEXUS_ALLOW_LOCAL_DB=1", "PATH=/usr/bin:/bin"}, extra...)
}

func readAndCheckClosed(t *testing.T) func(int) ([]byte, error) {
	return func(fd int) ([]byte, error) {
		raw, err := readDSNFD(fd)
		if !closed(fd) {
			t.Error("secret FD left open")
		}
		return raw, err
	}
}

// migrateViaPipe runs the --dsn-fd form.
func migrateViaPipe(t *testing.T, dsn string, env []string) error {
	fd := pipeFD(t, []byte(dsn+"\n"), false)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return runMigrateDSNFD(ctx, []string{"migrate", "--dsn-fd", strconv.Itoa(fd)}, env, readAndCheckClosed(t))
}

// migrateViaPasswordPipe runs the bootstrap form: public template in the
// environment, {"version":1,"dbPassword":…} on the FD.
func migrateViaPasswordPipe(t *testing.T, dsn string, env []string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := u.User.Password()
	u.User = url.User(u.User.Username())
	payload, _ := json.Marshal(map[string]any{"version": 1, "dbPassword": password})
	fd := pipeFD(t, payload, false)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return runMigrateDSNFD(ctx, []string{"migrate", "--db-password-fd", strconv.Itoa(fd)}, append(env, "NEXUS_MIGRATE_DSN="+u.String()), readAndCheckClosed(t))
}

func TestMigrateDSNFDSchema6To9(t *testing.T) {
	dsn := scramDSN(t)
	schema, role := schema6(t, dsn)
	before := relations(t, dsn, schema)
	if _, ok := before["message_edges"]; ok {
		t.Fatal("schema 6 fixture already has schema 9 tables")
	}
	if err := migrateViaPasswordPipe(t, dsn, fdEnv(schema, role)); err != nil {
		t.Fatal(err)
	}
	if v := versions(t, dsn, schema); v != [3]int{9, 1, 4} {
		t.Fatalf("after migrate: %v", v)
	}
	after := relations(t, dsn, schema)
	for _, table := range []string{"custody_approvals", "secret_values", "executor_credentials", "secret_plan_runs", "teams", "team_seats", "team_installs", "message_edges", "message_edge_marks"} {
		if after[table] != "r" {
			t.Fatalf("table %s missing: %v", table, after[table])
		}
	}
	for name, want := range map[string]string{
		"custody_approvals_hash":    "(account_id, input_hash, id)",
		"teams_account":             "(account_id, id)",
		"team_seats_team":           "(team_id, id)",
		"team_seats_active_session": "WHERE ((state = 'active'::text) AND (session_id <> ''::text))",
		"message_edges_reverse":     "(account_id, b, a)",
	} {
		if !strings.Contains(after[name], want) {
			t.Fatalf("index %s: %q", name, after[name])
		}
	}
	if _, old := after["message_edges_b"]; old {
		t.Fatal("earlier reverse index present")
	}
	// the earlier schema-9 reverse index is replaced by the ordered one
	adminExec(t, dsn, "SET ROLE "+pgx.Identifier{role}.Sanitize()+"; DROP INDEX "+pgx.Identifier{schema, "message_edges_reverse"}.Sanitize()+"; CREATE INDEX message_edges_b ON "+pgx.Identifier{schema, "message_edges"}.Sanitize()+"(account_id,b)")
	if err := migrateViaPipe(t, dsn, fdEnv(schema, role)); err != nil {
		t.Fatal(err)
	}
	after = relations(t, dsn, schema)
	if _, old := after["message_edges_b"]; old || !strings.Contains(after["message_edges_reverse"], "(account_id, b, a)") {
		t.Fatalf("index migration: %v", after)
	}
	// the migrated schema is owned by the SET ROLE identity, not the login
	var owner string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if err := conn.QueryRow(ctx, "SELECT tableowner FROM pg_tables WHERE schemaname=$1 AND tablename='message_edges'", schema).Scan(&owner); err != nil || owner != role {
		t.Fatalf("owner %q %v", owner, err)
	}
}

// holdAdvisory keeps a session advisory lock in another connection until cleanup.
func holdAdvisory(t *testing.T, dsn string, key int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
}

// Partial failure: each stage fails on its own; the stage is identified, the
// process stops (no retry, later stages not run) and a read-only readback
// reconciles exactly which steps took effect.
func TestMigrateDSNFDPartialFailureIdentifiesStage(t *testing.T) {
	dsn := scramDSN(t)
	t.Run("nexus", func(t *testing.T) {
		schema, role := schema6(t, dsn)
		holdAdvisory(t, dsn, 7302001) // pgstore.Migrate's lock
		err := migrateViaPipe(t, dsn, fdEnv(schema, role, "NEXUS_DB_LOCK_TIMEOUT_MS=300"))
		if err == nil || err.Error() != "nexus: migration failed (nexus)" {
			t.Fatal(err)
		}
		if v := versions(t, dsn, schema); v != [3]int{6, 1, 4} {
			t.Fatalf("nexus step is atomic, got %v", v)
		}
		if _, ok := relations(t, dsn, schema)["teams"]; ok {
			t.Fatal("schema 9 tables created by a failed step")
		}
	})
	t.Run("credentials", func(t *testing.T) {
		schema, role := schema6(t, dsn)
		holdAdvisory(t, dsn, 7302003) // gate credentials Migrate's lock
		err := migrateViaPipe(t, dsn, fdEnv(schema, role, "NEXUS_DB_LOCK_TIMEOUT_MS=300"))
		if err == nil || err.Error() != "nexus: migration failed (credentials)" {
			t.Fatal(err)
		}
		// reconciliation by readback: the nexus step committed, gate did not move
		if v := versions(t, dsn, schema); v != [3]int{9, 1, 4} {
			t.Fatalf("readback %v", v)
		}
		if _, ok := relations(t, dsn, schema)["teams"]; !ok {
			t.Fatal("nexus step result missing")
		}
	})
	t.Run("enrolments", func(t *testing.T) {
		schema, role := schema6(t, dsn)
		holdAdvisory(t, dsn, 7302004) // gate MigrateEnrolments' lock
		err := migrateViaPipe(t, dsn, fdEnv(schema, role, "NEXUS_DB_LOCK_TIMEOUT_MS=300"))
		if err == nil || err.Error() != "nexus: migration failed (enrolments)" {
			t.Fatal(err)
		}
		if v := versions(t, dsn, schema); v != [3]int{9, 1, 4} {
			t.Fatalf("readback %v", v)
		}
	})
	t.Run("overall budget", func(t *testing.T) {
		schema, role := schema6(t, dsn)
		holdAdvisory(t, dsn, 7302001)
		saved := migrateFDBudget
		migrateFDBudget = time.Second
		defer func() { migrateFDBudget = saved }()
		start := time.Now()
		err := migrateViaPasswordPipe(t, dsn, fdEnv(schema, role, "NEXUS_DB_LOCK_TIMEOUT_MS=60000"))
		if err == nil || err.Error() != "nexus: migration failed (nexus)" || time.Since(start) > 10*time.Second {
			t.Fatal(err, time.Since(start))
		}
		if v := versions(t, dsn, schema); v != [3]int{6, 1, 4} {
			t.Fatalf("readback %v", v)
		}
	})
	t.Run("connection lost mid-step", func(t *testing.T) {
		schema, role := schema6(t, dsn)
		// the nexus step blocks on its lock; its backend is then terminated
		holdAdvisory(t, dsn, 7302001)
		go func() {
			time.Sleep(500 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if conn, err := pgx.Connect(ctx, dsn); err == nil {
				_, _ = conn.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND objid=7302001 AND NOT granted")
				conn.Close(ctx)
			}
		}()
		err := migrateViaPipe(t, dsn, fdEnv(schema, role, "NEXUS_DB_LOCK_TIMEOUT_MS=5000"))
		if err == nil || err.Error() != "nexus: migration failed (nexus)" {
			t.Fatal(err)
		}
		if v := versions(t, dsn, schema); v != [3]int{6, 1, 4} {
			t.Fatalf("readback %v", v)
		}
	})
}

// SCRAM-only against the real server: a role whose pg_hba method is md5 or
// password is refused before any PasswordMessage, while the superuser
// (scram-sha-256) works. The disposable cluster's pg_hba must route
// nts_md5_fixture to md5 and nts_password_fixture to password.
func TestMigrateDSNFDRefusesNonSCRAMServers(t *testing.T) {
	dsn := scramDSN(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	for user, password := range map[string]string{"nts_md5_fixture": "public-md5-fixture-pw-01", "nts_password_fixture": "public-cleartext-fixture-pw-01"} {
		t.Run(user, func(t *testing.T) {
			v := *u
			v.User = url.UserPassword(user, password)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			control, err := pgx.Connect(ctx, v.String())
			if err != nil {
				t.Skip("fixture role not configured on this cluster")
			}
			control.Close(ctx)
			for _, migrate := range []func(*testing.T, string, []string) error{migrateViaPipe, migrateViaPasswordPipe} {
				err = migrate(t, v.String(), fdEnv("fd_scram_refusal", "pg_read_all_data"))
				if err == nil || !strings.HasPrefix(err.Error(), "nexus: database connection failed (") || strings.Contains(err.Error(), password) {
					t.Fatal(err)
				}
			}
		})
	}
}
