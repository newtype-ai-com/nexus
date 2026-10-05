package nexusserver

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSealingConfigRequiresCompleteSettings(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1"}
	get := func(k string) string { return base[k] }
	complete := map[string]string{"SEAL_MASTER": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "DELEGATION_SIGNING_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "SIGNING_KID": "fixture-v1", "SEAL_ISSUER": "https://example.test"}
	for key, value := range complete {
		base[key] = value
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatal("partial sealing accepted")
		}
		delete(base, key)
	}
	for key, value := range complete {
		base[key] = value
	}
	if cfg, err := ConfigFromEnv(get); err != nil || cfg.Sealer == nil {
		t.Fatal("complete sealing rejected")
	}
	for _, issuer := range []string{"http://example.test", "https://user@example.test", "https://example.test/path", "https://example.test?x=y"} {
		base["SEAL_ISSUER"] = issuer
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatal("invalid issuer accepted")
		}
	}
}

func TestEnrolmentConfigRequiresCompleteSettings(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1"}
	get := func(k string) string { return base[k] }
	if cfg, err := ConfigFromEnv(get); err != nil || cfg.EnrolmentConfig != nil {
		t.Fatal("default enrolment enabled")
	}
	for _, key := range []string{"BASE_URL", "ENROL_ALLOW", "MAIL_FROM", "RESEND_API_KEY", "ADMIN_TOKEN"} {
		base[key] = "fixture"
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatal("partial configuration accepted")
		}
		delete(base, key)
	}
	base["BASE_URL"] = "https://example.test"
	base["ENROL_ALLOW"] = "example.test"
	base["MAIL_FROM"] = "sender@example.test"
	base["RESEND_API_KEY"] = "fixture"
	if cfg, err := ConfigFromEnv(get); err != nil || cfg.EnrolmentConfig == nil {
		t.Fatal("complete configuration rejected")
	}
}

func TestAdminTokenMinimumLength(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1",
		"BASE_URL": "https://example.test", "ENROL_ALLOW": "example.test", "MAIL_FROM": "sender@example.test", "RESEND_API_KEY": "fixture"}
	get := func(k string) string { return base[k] }
	for _, tc := range []struct {
		token string
		ok    bool
	}{
		{"", true},
		{strings.Repeat("a", MinAdminTokenLength-1), false},
		{strings.Repeat("a", MinAdminTokenLength), true},
		{strings.Repeat("0f", 32), true}, // openssl rand -hex 32
	} {
		base["ADMIN_TOKEN"] = tc.token
		cfg, err := ConfigFromEnv(get)
		if (err == nil) != tc.ok {
			t.Fatalf("ADMIN_TOKEN length %d: err=%v", len(tc.token), err)
		}
		if err != nil && strings.Contains(err.Error(), tc.token) {
			t.Fatal("error echoes the token")
		}
		if err == nil && cfg.EnrolmentConfig.AdminToken != tc.token {
			t.Fatal("ADMIN_TOKEN not carried")
		}
	}
}

// BBP-R1: SCRAM-only database authentication is on for every production
// (non-development) configuration and cannot be switched off there.
func TestDBRequireSCRAMDefaultsOnForProduction(t *testing.T) {
	prod := map[string]string{"DATABASE_URL": "postgres://nexus_runtime@db.example:5432/db?sslmode=verify-full", "NEXUS_DB_SCHEMA": "newtype_test"}
	dev := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1"}
	for _, tc := range []struct {
		name    string
		base    map[string]string
		setting string
		want    bool
		ok      bool
	}{
		{"production default", prod, "", true, true},
		{"production explicit", prod, "1", true, true},
		{"production opt-out refused", prod, "0", false, false},
		{"production invalid", prod, "true", false, false},
		{"development default", dev, "", false, true},
		{"development explicit", dev, "1", true, true},
		{"development opt-out", dev, "0", false, true},
		{"development invalid", dev, "yes", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			get := func(k string) string {
				if k == "NEXUS_DB_REQUIRE_SCRAM" {
					return tc.setting
				}
				return tc.base[k]
			}
			cfg, err := ConfigFromEnv(get)
			if (err == nil) != tc.ok || (err == nil && cfg.DBRequireSCRAM != tc.want) {
				t.Fatalf("err=%v require=%v", err, cfg.DBRequireSCRAM)
			}
		})
	}
	// Loopback without the explicit development flag is production.
	loop := map[string]string{"DATABASE_URL": "postgres://nexus_runtime@127.0.0.1:5432/db?sslmode=verify-full", "NEXUS_DB_SCHEMA": "newtype_test"}
	if cfg, err := ConfigFromEnv(func(k string) string { return loop[k] }); err != nil || !cfg.DBRequireSCRAM {
		t.Fatalf("loopback production config: err=%v require=%v", err, cfg.DBRequireSCRAM)
	}
}

func TestReleasesDirConfig(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1"}
	get := func(k string) string { return base[k] }
	if cfg, err := ConfigFromEnv(get); err != nil || cfg.ReleasesDir != "" {
		t.Fatal("releases enabled by default")
	}
	base["NEXUS_RELEASES_DIR"] = "/data/releases"
	if cfg, err := ConfigFromEnv(get); err != nil || cfg.ReleasesDir != "/data/releases" {
		t.Fatalf("valid releases dir rejected: %v", err)
	}
	for _, dir := range []string{"data/releases", "/data/../etc", "/data/releases/", "/data/rel\neases"} {
		base["NEXUS_RELEASES_DIR"] = dir
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatalf("invalid releases dir %q accepted", dir)
		}
	}
}
