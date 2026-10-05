package nexusserver

import (
	"strings"
	"testing"
	"time"
)

func TestModelCallBudgetEnv(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"DATABASE_URL": "postgres://fixture:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1",
			"MODEL_UPSTREAM": "https://fixture.invalid/responses", "MODEL_API_KEY": "fixture-secret", "MODEL_NAMES": "example-model", "MODEL_TOKEN_CEILING": "4096", "MODEL_MAX_OUTPUT": "256",
		}
	}
	for _, tc := range []struct {
		key, value string
		valid      bool
	}{
		{"MODEL_CALL_BUDGET_FILE", "/var/lib/newtype-model-budget/calls.jsonl", true},
		{"MODEL_CALL_BUDGET_FILE", "relative.jsonl", false},
		{"MODEL_CALL_BUDGET_FILE", "/tmp/../calls.jsonl", false},
		{"MODEL_CALL_BUDGET_FILE", "/tmp/calls\n.jsonl", false},
		{"MODEL_TURN_TIMEOUT_SECONDS", "1", true}, {"MODEL_TURN_TIMEOUT_SECONDS", "900", true},
		{"MODEL_TURN_TIMEOUT_SECONDS", "0", false}, {"MODEL_TURN_TIMEOUT_SECONDS", "901", false},
		{"MODEL_TURN_TIMEOUT_SECONDS", "1.5", false}, {"MODEL_TURN_TIMEOUT_SECONDS", "-1", false},
	} {
		env := base()
		env[tc.key] = tc.value
		cfg, err := ConfigFromEnv(func(k string) string { return env[k] })
		if (err == nil) != tc.valid {
			t.Fatalf("%s unexpected validation", tc.key)
		}
		if err != nil && strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("secret leaked")
		}
		if tc.valid && tc.key == "MODEL_CALL_BUDGET_FILE" && cfg.ModelConfig.CallBudgetFile != tc.value {
			t.Fatal("missing ledger")
		}
		if tc.valid && tc.value == "900" && cfg.ModelConfig.TurnLimit != 900*time.Second {
			t.Fatal("missing timeout")
		}
	}
	for _, key := range []string{"MODEL_CALL_BUDGET_FILE", "MODEL_TURN_TIMEOUT_SECONDS"} {
		env := base()
		delete(env, "MODEL_UPSTREAM")
		delete(env, "MODEL_API_KEY")
		env[key] = "1"
		if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Fatal("orphan setting accepted")
		}
	}
}
