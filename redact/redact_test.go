package redact

import (
	"strings"
	"testing"
)

func TestPatterns(t *testing.T) {
	tests := map[string]string{
		"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----",
		"nts_licence":    "ntl_" + strings.Repeat("x", 20),
		"nts_login":      "ntg_" + strings.Repeat("x", 20),
		"enrol_poll":     "enp_" + strings.Repeat("x", 20),
		"enrol_verify":   "vfy_" + strings.Repeat("x", 20),
		"nts_bootstrap":  "ntb_" + strings.Repeat("x", 20),
		"nts_agent":      "nta_" + strings.Repeat("x", 20),
		"anthropic_key":  "sk-ant-" + strings.Repeat("x", 25),
		"openai_key":     "sk-proj-" + strings.Repeat("x", 25),
		"github_token":   "github_pat_" + strings.Repeat("x", 45),
		"slack_token":    "xoxb-" + strings.Repeat("x", 12),
		"aws_access_key": "AKIA" + strings.Repeat("X", 16),
		"google_api_key": "AIza" + strings.Repeat("x", 35),
		"resend_key":     "re_" + strings.Repeat("x", 8) + "_" + strings.Repeat("x", 16),
		"jwt":            "eyJ" + strings.Repeat("x", 10) + "." + strings.Repeat("y", 12) + "." + strings.Repeat("z", 12),
		"bearer_token":   "Bearer " + strings.Repeat("x", 25),
		"password":       "password: hunter2hunter2",
		"card_number":    "4111 1111 1111 1111",
	}
	for kind, text := range tests {
		t.Run(kind, func(t *testing.T) {
			got, n := Text(text)
			if got != "[secret:"+kind+"]" || n != 1 {
				t.Fatalf("%q count %d", got, n)
			}
		})
	}
}
func TestPlainAndIdempotence(t *testing.T) {
	for _, text := range []string{"exit code: 0", "2026-09-30T00:00:00Z", "the password field is required", "4111111111111112", "secret://NAME", "[secret:nts_agent]", "evt_01M3TXAQEH0PK0Z25MB9KGRX7H"} {
		got, n := Text(text)
		if got != text || n != 0 {
			t.Fatalf("plain changed %q => %q", text, got)
		}
	}
	got, n := Text("password: ntl_" + strings.Repeat("x", 20))
	if n != 1 || !strings.Contains(got, "[secret:nts_licence]") {
		t.Fatal(got, n)
	}
	again, n := Text(got)
	if again != got || n != 0 {
		t.Fatal(again, n)
	}
}
func TestJSON(t *testing.T) {
	input := []byte(`{"n":9007199254740993,"nested":[{"password: hunter2hunter2":"sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxx"}],"ok":true}`)
	got, n, err := JSON(input)
	if err != nil || n != 2 || !strings.Contains(string(got), `9007199254740993`) || strings.Contains(string(got), "hunter2") {
		t.Fatalf("%s %d %v", got, n, err)
	}
	for _, bad := range []string{`{`, `null true`, `{"a":1,"a":2}`, `{"password: abcdefgh":1,"password: ijklmnop":2}`, `[1,]`, `{"x":`} {
		if _, _, err := JSON([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
