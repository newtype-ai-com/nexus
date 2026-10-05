// Package modelerror extracts bounded diagnostic labels, never provider messages.
package modelerror

import (
	"encoding/json"
	"strings"
)

const MaxEnvelope = 64 * 1024

// Detail contains only protocol code/type labels and a retry classification.
// Unknown or malformed errors fail closed as permanent.
type Detail struct {
	Code, Type string
	Transient  bool
}

func label(s string) string {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return ""
		}
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// FailureCode is the shared M17 diagnostic label used by clients and Gate.
func (d Detail) FailureCode() string {
	if d.Code != "" {
		return d.Code
	}
	if d.Type != "" {
		return d.Type
	}
	return "unknown"
}

func (d Detail) Error() string {
	s := d.FailureCode() + ": model stream returned an error"
	if d.Type != "" {
		s += " type=" + d.Type
	}
	return s
}
func (d Detail) Permanent() bool { return !d.Transient }

// Parse is for an already identified error event. Context heuristics, if needed,
// are separate: no message/body is retained in the diagnostic object.
func Parse(raw []byte) Detail {
	var out Detail
	if len(raw) > MaxEnvelope {
		return out
	}
	var e struct {
		Error    json.RawMessage `json:"error"`
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return out
	}
	var response struct {
		Error json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(e.Response, &response)
	// Read each envelope independently, in reference order. Empty or malformed
	// siblings must not hide a later valid code. Event types are not error types.
	candidates := []json.RawMessage{raw, e.Error, response.Error}
	permanent := false
	for i, candidate := range candidates {
		var d struct {
			Code   json.RawMessage `json:"code"`
			Type   json.RawMessage `json:"type"`
			Status json.RawMessage `json:"status"`
		}
		if json.Unmarshal(candidate, &d) != nil {
			continue
		}
		var code, kind string
		if json.Unmarshal(d.Code, &code) != nil {
			var n json.Number
			if json.Unmarshal(d.Code, &n) == nil {
				code = n.String()
			}
		}
		_ = json.Unmarshal(d.Type, &kind)
		if i == 0 && (kind == "error" || kind == "response.failed") {
			kind = ""
		}
		if kind == "" {
			_ = json.Unmarshal(d.Status, &kind)
		}
		if out.Code == "" {
			out.Code = label(code)
		}
		if out.Type == "" {
			out.Type = label(kind)
		}
		// Classify full labels, not truncated prefixes. Permanent signals win
		// even if a different envelope advertises a transient error.
		for _, s := range []string{code, kind} {
			switch strings.ToLower(s) {
			case "authentication_error", "permission_error", "invalid_request_error", "invalid_argument", "unauthenticated", "permission_denied", "400", "401", "403", "404", "422":
				permanent = true
			case "rate_limit_exceeded", "rate_limit_error", "rate_limited", "insufficient_quota", "quota_exceeded", "resource_exhausted", "overloaded_error", "overloaded", "server_error", "internal_error", "internal_server_error", "internal", "unavailable", "service_unavailable", "429", "500", "502", "503", "504", "529":
				out.Transient = true
			}
		}
	}
	if permanent {
		out.Transient = false
	}
	return out
}

// IsEvent recognizes only protocol-level error envelopes, not content/tool text.
func IsEvent(raw []byte, event string) bool {
	if event == "error" || event == "response.failed" {
		return true
	}
	if len(raw) > MaxEnvelope {
		return false
	}
	var e struct {
		Type  string          `json:"type"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return false
	}
	return e.Type == "error" || e.Type == "response.failed" || len(e.Error) != 0 && string(e.Error) != "null"
}
