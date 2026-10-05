package nexusserver

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestOperatorDefaultModelConfig(t *testing.T) {
	full := map[string]string{
		"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1",
		"MS_FOUNDRY_PROJECT_ENDPOINT": "https://fixture.services.ai.azure.com", "MS_FOUNDRY_API_KEY": "fixture-key-0123456789", "MODEL_PROTOCOL": "responses",
		"MODEL_NAMES": "example-model", "MODEL_TOKEN_CEILING": "1000", "MODEL_MAX_OUTPUT": "100",
		"NEXUS_OWNER_EMAIL": "owner@example.test",
		"SEAL_MASTER":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "DELEGATION_SIGNING_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "SIGNING_KID": "fixture-v1", "SEAL_ISSUER": "https://example.test",
		"MODEL_OPERATOR_STORE": "/var/lib/nexus/operator/default-model.sealed", "MODEL_OPERATOR_APPROVALS_URL": "http://127.0.0.1:8471", "MODEL_OPERATOR_APPROVALS_TOKEN": strings.Repeat("T", 40),
	}
	load := func(change map[string]string) error {
		env := map[string]string{}
		for k, v := range full {
			env[k] = v
		}
		for k, v := range change {
			env[k] = v
		}
		_, err := ConfigFromEnv(func(k string) string { return env[k] })
		return err
	}
	if err := load(nil); err != nil {
		t.Fatal(err)
	}
	// Env stays the bootstrap; operator settings remain optional.
	if err := load(map[string]string{"MODEL_OPERATOR_STORE": "", "MODEL_OPERATOR_APPROVALS_URL": "", "MODEL_OPERATOR_APPROVALS_TOKEN": ""}); err != nil {
		t.Fatal(err)
	}
	// Stored value readable at startup even when changes are not configured.
	if err := load(map[string]string{"MODEL_OPERATOR_APPROVALS_URL": "", "MODEL_OPERATOR_APPROVALS_TOKEN": ""}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]map[string]string{
		"no sealing":         {"SEAL_MASTER": "", "DELEGATION_SIGNING_KEY": "", "SIGNING_KID": "", "SEAL_ISSUER": ""},
		"no owner":           {"NEXUS_OWNER_EMAIL": ""},
		"no model":           {"MS_FOUNDRY_PROJECT_ENDPOINT": "", "MS_FOUNDRY_API_KEY": "", "MODEL_PROTOCOL": "", "MODEL_NAMES": "", "MODEL_TOKEN_CEILING": "", "MODEL_MAX_OUTPUT": ""},
		"relative store":     {"MODEL_OPERATOR_STORE": "operator/default-model.sealed"},
		"approvals no store": {"MODEL_OPERATOR_STORE": ""},
		"url without token":  {"MODEL_OPERATOR_APPROVALS_TOKEN": ""},
		"remote plain http":  {"MODEL_OPERATOR_APPROVALS_URL": "http://approvals.example.com"},
		"short token":        {"MODEL_OPERATOR_APPROVALS_TOKEN": "short"},
	} {
		if err := load(change); err == nil {
			t.Fatalf("%s accepted", name)
		} else if strings.Contains(err.Error(), "fixture-key") || strings.Contains(err.Error(), "TTTT") {
			t.Fatalf("%s: secret in error", name)
		}
	}
}
