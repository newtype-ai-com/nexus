package nexusserver

import "testing"

func TestDBSessionConfig(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1", "NEXUS_DB_ROLE": "nexus_migrator", "NEXUS_DB_STATEMENT_TIMEOUT_MS": "60000", "NEXUS_DB_LOCK_TIMEOUT_MS": "5000"}
	get := func(k string) string { return base[k] }
	cfg, err := ConfigFromEnv(get)
	if err != nil || cfg.DBRole != "nexus_migrator" || cfg.DBStatementTimeoutMS != 60000 || cfg.DBLockTimeoutMS != 5000 {
		t.Fatalf("session config: %v", err)
	}
	for key, values := range map[string][]string{
		"NEXUS_DB_ROLE":                 {"bad;role", "role name"},
		"NEXUS_DB_STATEMENT_TIMEOUT_MS": {"-1", "0", "bad", "2147483648"},
		"NEXUS_DB_LOCK_TIMEOUT_MS":      {"-1", "0", "5s", "2147483648"},
	} {
		old := base[key]
		for _, value := range values {
			base[key] = value
			if _, err := ConfigFromEnv(get); err == nil {
				t.Fatalf("accepted invalid %s", key)
			}
		}
		base[key] = old
	}
}
