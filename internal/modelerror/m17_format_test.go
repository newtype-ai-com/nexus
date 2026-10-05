package modelerror

import "testing"

func TestM17EnvelopeFallbackAndFormat(t *testing.T) {
	for _, tc := range []struct {
		name, raw, code, kind string
		transient             bool
	}{
		{"root-first", `{"type":"error","code":"root_code","error":{"code":"nested_code","type":"custom"},"response":{"error":{"code":"last_code"}}}`, "root_code", "custom", false},
		{"empty-error", `{"type":"response.failed","error":{},"response":{"error":{"code":"server_error"}}}`, "server_error", "", true},
		{"null-error", `{"error":null,"response":{"error":{"code":503}}}`, "503", "", true},
		{"malformed-sibling", `{"error":"PRIVATE BODY","response":{"error":{"code":"server_error"}}}`, "server_error", "", true},
		{"malformed-type", `{"type":{},"code":"server_error","error":{}}`, "server_error", "", true},
		{"malformed-code", `{"code":{},"error":{"code":"rate_limit_exceeded"}}`, "rate_limit_exceeded", "", true},
		{"invalid-label", `{"code":"bad\nPRIVATE","error":{"code":"server_error"}}`, "server_error", "", true},
		{"split-fields", `{"code":"429","error":{"type":"rate_limit_error"}}`, "429", "rate_limit_error", true},
		{"permanent-wins", `{"code":"server_error","response":{"error":{"type":"authentication_error"}}}`, "server_error", "authentication_error", false},
		{"nested-permanent-wins", `{"type":"error","error":{"code":"server_error"},"response":{"error":{"type":"permission_error"}}}`, "server_error", "permission_error", false},
		{"unknown", `{"type":"response.failed","message":"PRIVATE BODY","response":{"error":{}}}`, "", "", false},
		{"type-only", `{"type":"error","error":{"type":"overloaded_error","message":"PRIVATE BODY"}}`, "", "overloaded_error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Parse([]byte(tc.raw))
			if d.Code != tc.code || d.Type != tc.kind || d.Transient != tc.transient {
				t.Fatalf("unexpected diagnostic: %+v", d)
			}
			failed := tc.code
			if failed == "" {
				failed = tc.kind
			}
			if failed == "" {
				failed = "unknown"
			}
			want := failed + ": model stream returned an error"
			if tc.kind != "" {
				want += " type=" + tc.kind
			}
			if d.FailureCode() != failed || d.Error() != want {
				t.Fatalf("diagnostic format: %q want %q", d.Error(), want)
			}
		})
	}
}
