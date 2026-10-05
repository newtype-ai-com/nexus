package nexusserver

import (
	"strings"
	"testing"
)

// Section 2, negative case 8. No DB is opened by ConfigFromEnv.
func TestIndependentBottleneckOwnerOnlyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, flag, owner string
		valid             bool
	}{
		{"strict_without_owner", "1", "", false},
		{"strict_valid_owner", "1", "owner@example.test", true},
		{"strict_normalized_owner", "1", " Owner@Example.test ", true},
		{"strict_domain_not_owner", "1", "example.test", false},
		{"strict_wildcard_not_owner", "1", "*@example.test", false},
		{"strict_multiple_owners", "1", "a@example.test,b@example.test", false},
		{"disabled_without_owner", "0", "", true},
		{"unset_without_owner", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"DATABASE_URL":         "postgres://fixture:synthetic-password@127.0.0.1/unused?sslmode=disable",
				"NEXUS_DB_SCHEMA":      "independent_unused",
				"NEXUS_ALLOW_LOCAL_DB": "1",
				"NEXUS_OWNER_ONLY":     tc.flag,
				"NEXUS_OWNER_EMAIL":    tc.owner,
			}
			cfg, err := ConfigFromEnv(func(k string) string { return env[k] })
			if (err == nil) != tc.valid {
				t.Fatalf("configuration accepted=%t, want %t", err == nil, tc.valid)
			}
			if tc.valid && tc.owner != "" && cfg.OwnerEmail != "owner@example.test" {
				t.Fatal("owner normalization changed")
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-password") {
				t.Fatal("configuration error exposes credential sentinel")
			}
		})
	}
}

// Section 3: configuration rejection must not echo rejected credential values.
// These are synthetic sentinels, not registered or operational credentials.
func TestIndependentBottleneckConfigErrorsDoNotEchoSecrets(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"DATABASE_URL", "postgres://fixture:SYNTHETIC-DB-PASSWORD@127.0.0.1/%zz"},
		{"RESEND_API_KEY", "SYNTHETIC-MAIL-KEY"},
		{"ADMIN_TOKEN", "SYNTHETIC-ADMIN-TOKEN"},
		{"MODEL_API_KEY", "SYNTHETIC-MODEL-KEY"},
		{"SEAL_MASTER", "SYNTHETIC-SEAL-KEY"},
		{"DELEGATION_SIGNING_KEY", "SYNTHETIC-SIGNING-KEY"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			env := map[string]string{
				"DATABASE_URL":    "postgres://fixture:synthetic-password@127.0.0.1/unused?sslmode=disable",
				"NEXUS_DB_SCHEMA": "independent_unused", "NEXUS_ALLOW_LOCAL_DB": "1",
			}
			env[tc.key] = tc.value
			_, err := ConfigFromEnv(func(k string) string { return env[k] })
			if err == nil {
				t.Fatal("invalid partial configuration accepted")
			}
			for _, sentinel := range []string{tc.value, "synthetic-password", "SYNTHETIC-DB-PASSWORD"} {
				if strings.Contains(err.Error(), sentinel) {
					t.Fatal("configuration error exposes synthetic credential")
				}
			}
		})
	}
}
