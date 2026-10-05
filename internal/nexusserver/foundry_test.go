package nexusserver

import (
	"strings"
	"testing"
)

func TestFoundryModelEndpoint(t *testing.T) {
	for _, base := range []string{"https://fixture.services.ai.azure.com", "https://fixture.services.ai.azure.com/api/projects/demo", "https://fixture.services.ai.azure.com/api/projects/demo/", "https://fixture.services.ai.azure.com/openai", "https://fixture.services.ai.azure.com/openai/", "https://fixture.services.ai.azure.com/openai/v1/", "https://fixture.openai.azure.com/"} {
		for _, protocol := range []string{"", "chat/completions", "responses"} {
			got, err := foundryModelEndpoint(base, protocol)
			wantProtocol := protocol
			if wantProtocol == "" {
				wantProtocol = "chat/completions"
			}
			if err != nil || !strings.HasSuffix(got, "/openai/v1/"+wantProtocol) || strings.Contains(got, "/projects/") {
				t.Fatalf("endpoint normalization failed: %v", err)
			}
		}
	}
	for _, base := range []string{"http://fixture.services.ai.azure.com", "https://fixture.services.ai.azure.com.evil.test", "https://127.0.0.1", "https://user:secret@fixture.services.ai.azure.com", "https://fixture.services.ai.azure.com:443", "https://fixture.services.ai.azure.com?secret=value", "https://fixture.services.ai.azure.com?", "https://fixture.services.ai.azure.com#", "https://fixture.services.ai.azure.com/#secret", "https://fixture.services.ai.azure.com/api/projects/../demo", "https://fixture.services.ai.azure.com/api/projects/%64emo", "https://fixture.openai.azure.com/api/projects/demo", "https://fixture.services.ai.azure.com/arbitrary", "https://fixture.services.ai.azure.com/openai/deployments/demo"} {
		if _, err := foundryModelEndpoint(base, "responses"); err == nil || strings.Contains(err.Error(), base) {
			t.Fatal("unsafe endpoint accepted or echoed")
		}
	}
	if _, err := foundryModelEndpoint("https://fixture.services.ai.azure.com", "agents"); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
}

func TestFoundryConfig(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1",
			"MS_FOUNDRY_PROJECT_ENDPOINT": "https://fixture.services.ai.azure.com/api/projects/demo", "MS_FOUNDRY_API_KEY": "fixture-secret",
			"MODEL_NAMES": "actual-deployment", "MODEL_TOKEN_CEILING": "4096", "MODEL_MAX_OUTPUT": "128", "MODEL_PROTOCOL": "responses",
		}
	}
	env := base()
	cfg, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil || cfg.ModelConfig == nil || cfg.ModelConfig.Upstream != "https://fixture.services.ai.azure.com/openai/v1/responses" || cfg.ModelConfig.Key != "fixture-secret" || cfg.ModelConfig.Models[0] != "actual-deployment" {
		t.Fatal("complete Foundry configuration rejected")
	}
	for _, missing := range []string{"MS_FOUNDRY_PROJECT_ENDPOINT", "MS_FOUNDRY_API_KEY", "MODEL_NAMES", "MODEL_TOKEN_CEILING", "MODEL_MAX_OUTPUT"} {
		env = base()
		delete(env, missing)
		if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("partial configuration accepted or secret echoed")
		}
	}
	for _, mixed := range []string{"MODEL_UPSTREAM", "MODEL_API_KEY"} {
		env = base()
		env[mixed] = "fixture"
		if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Fatal("ambiguous provider configuration accepted")
		}
	}
}
