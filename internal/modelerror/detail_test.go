package modelerror

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiagnosticPrivacyAndClassification(t *testing.T) {
	for _, tc := range []struct {
		raw, code, kind string
		retry           bool
	}{
		{`{"error":{"code":"rate_limit_exceeded","type":"rate_limit_error","message":"PRIVATE BODY"}}`, "rate_limit_exceeded", "rate_limit_error", true},
		{`{"type":"response.failed","response":{"error":{"code":"insufficient_quota","message":"PRIVATE BODY"}}}`, "insufficient_quota", "", true},
		{`{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"PRIVATE BODY"}}`, "429", "RESOURCE_EXHAUSTED", true},
		{`{"error":{"type":"overloaded_error"}}`, "", "overloaded_error", true},
		{`{"error":{"code":503}}`, "503", "", true},
		{`{"error":{"code":"server_error","type":"authentication_error"}}`, "server_error", "authentication_error", false},
		{`{"error":{"type":"invalid_request_error"}}`, "", "invalid_request_error", false},
		{`{"error":{"code":"unknown.code-1","type":"custom"}}`, "unknown.code-1", "custom", false},
		{`{"error":{"code":"bad\nPRIVATE","type":"한글"}}`, "", "", false},
		{`{"error":{"code":{},"type":"custom"}}`, "", "custom", false},
		{`not json PRIVATE`, "", "", false},
		{strings.Repeat("x", MaxEnvelope+1), "", "", false},
	} {
		d := Parse([]byte(tc.raw))
		if d.Code != tc.code || d.Type != tc.kind || d.Transient != tc.retry || d.Permanent() == tc.retry || strings.Contains(d.Error(), "PRIVATE") {
			t.Fatalf("%+v", d)
		}
	}
	raw, _ := json.Marshal(map[string]any{"error": map[string]string{"code": strings.Repeat("a", 100), "type": strings.Repeat("b", 100)}})
	d := Parse(raw)
	if len(d.Code) != 64 || len(d.Type) != 64 {
		t.Fatal(d)
	}
	raw, _ = json.Marshal(map[string]any{"error": map[string]string{"code": strings.Repeat("a", 100) + "\nPRIVATE"}})
	if Parse(raw).Code != "" {
		t.Fatal("invalid suffix hidden by truncation")
	}
	if IsEvent([]byte(`{"choices":[{"delta":{"content":"error"}}]}`), "") {
		t.Fatal("content treated as error")
	}
}
