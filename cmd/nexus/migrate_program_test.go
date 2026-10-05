//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// BBP-R4 (P5a): the migrator as a separate program in the exact bootstrap
// form — argv [binary, migrate, --db-password-fd, 30], an environment holding
// only the public MIGRATE_ENV keys, the {"version":1,"dbPassword":…} payload on
// an anonymous pipe at FD 30 — and the exact stdout response predicate.

// The test binary re-executes itself as the program when invoked as "nexus".
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "nexus" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runMigratorProgram(t *testing.T, env []string, payload []byte) (int, []byte, []byte) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "nexus")
	if err := os.Symlink(self, bin); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	w.Close()
	cmd := exec.Command(bin, "migrate", "--db-password-fd", "30")
	cmd.Env = env
	cmd.Dir = "/"
	cmd.ExtraFiles = make([]*os.File, 28) // index i -> FD 3+i; nil entries stay closed
	cmd.ExtraFiles[27] = r
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(150 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("migrator program did not finish")
	}
	return cmd.ProcessState.ExitCode(), stdout.Bytes(), stderr.Bytes()
}

func migrateEnvFor(t *testing.T, dsn, schema, role string) ([]string, []byte) {
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := u.User.Password()
	u.User = url.User(u.User.Username())
	payload, _ := json.Marshal(map[string]any{"version": 1, "dbPassword": password})
	return []string{"NEXUS_MIGRATE_DSN=" + u.String(), "NEXUS_DB_SCHEMA=" + schema, "NEXUS_DB_ROLE=" + role,
		"NEXUS_DB_STATEMENT_TIMEOUT_MS=30000", "NEXUS_DB_LOCK_TIMEOUT_MS=5000", "NEXUS_ALLOW_LOCAL_DB=1"}, payload
}

func TestMigratorProgramExactResponse(t *testing.T) {
	dsn := scramDSN(t)
	schema, role := schema6(t, dsn)
	env, payload := migrateEnvFor(t, dsn, schema, role)
	code, stdout, stderr := runMigratorProgram(t, env, payload)
	if code != 0 || string(stdout) != migrationsComplete+"\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if v := versions(t, dsn, schema); v != [3]int{9, 1, 4} {
		t.Fatalf("readback after success line: %v", v)
	}
	// A failure prints nothing on stdout (never the success line) and exits 1.
	bad := append([]byte(nil), payload...)
	bad = bytes.Replace(bad, []byte(`"dbPassword":"`), []byte(`"dbPassword":"wrong-`), 1)
	code, stdout, stderr = runMigratorProgram(t, env, bad)
	if code != 1 || len(stdout) != 0 || !bytes.HasPrefix(stderr, []byte("nexus: database connection failed (")) {
		t.Fatalf("failure: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if bytes.Contains(stderr, payload) || bytes.Contains(stderr, []byte("wrong-")) {
		t.Fatal("stderr echoes the password")
	}
	// Ambient database settings are refused before the FD is read.
	code, stdout, _ = runMigratorProgram(t, append(env, "PGPASSWORD=x"), payload)
	if code != 1 || len(stdout) != 0 {
		t.Fatalf("ambient: exit=%d stdout=%q", code, stdout)
	}
}
