package nexusserver

import "testing"

func TestOwnerOnlyConfiguration(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1", "NEXUS_OWNER_EMAIL": "Owner@Example.test"}
	get := func(k string) string { return base[k] }
	c, err := ConfigFromEnv(get)
	if err != nil || c.OwnerEmail != "owner@example.test" || c.EnrolmentConfig != nil {
		t.Fatal("owner should restrict existing access with enrolment disabled")
	}
	base["BASE_URL"] = "https://example.test"
	base["RESEND_API_KEY"] = "fixture"
	base["MAIL_FROM"] = "admission@newtype-ai.com"
	for _, allow := range []string{"example.test", "other@example.test", "owner@example.test,other@example.test", "*", ""} {
		base["ENROL_ALLOW"] = allow
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatalf("broad allowlist accepted: %s", allow)
		}
	}
	base["ENROL_ALLOW"] = "owner@example.test"
	if _, err := ConfigFromEnv(get); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"example.test", "*@example.test", "one@example.test,two@example.test"} {
		base["NEXUS_OWNER_EMAIL"] = owner
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatal("invalid owner accepted")
		}
	}
}

// L4: the operator owner-code route is opt-in and needs an owner + enrolment.
func TestOwnerCodeIsOptIn(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1", "NEXUS_OWNER_EMAIL": "owner@example.test", "BASE_URL": "https://example.test", "RESEND_API_KEY": "fixture", "MAIL_FROM": "admission@example.test", "ENROL_ALLOW": "owner@example.test"}
	get := func(k string) string { return base[k] }
	if c, err := ConfigFromEnv(get); err != nil || c.OwnerCode || c.EnrolmentConfig.OwnerCode {
		t.Fatal("owner code on by default")
	}
	base["NEXUS_OWNER_CODE"] = "1"
	if c, err := ConfigFromEnv(get); err != nil || !c.OwnerCode || !c.EnrolmentConfig.OwnerCode {
		t.Fatal("owner code not enabled", err)
	}
	for _, v := range []string{"true", "2", "yes"} {
		base["NEXUS_OWNER_CODE"] = v
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
	base["NEXUS_OWNER_CODE"] = "1"
	delete(base, "NEXUS_OWNER_EMAIL")
	base["ENROL_ALLOW"] = "example.test"
	if _, err := ConfigFromEnv(get); err == nil {
		t.Fatal("owner code without owner accepted")
	}
}
