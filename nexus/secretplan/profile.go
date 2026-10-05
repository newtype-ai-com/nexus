package secretplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"unicode/utf8"
)

// plan/3 consumer profiles, payload schemas and delivery (schema ruling §1).
const (
	ProfileAExecutor = "a-executor/1" // fixed A roles/FDs/schemas, enum output
	ProfileGeneric   = "generic/1"

	PayloadOpaque        = "opaque-bytes/1"        // generic Nexus values only, never A
	PayloadRuntime       = "runtime-wire/1"        // the frozen Keychain helper output
	PayloadDBAdmin       = "db-admin-wire/1"       // A db-admin role
	PayloadApprovalAdmin = "approval-admin-wire/1" // A approval-admin role

	// DeliveryTyped: the validated payload bytes, unchanged, then EOF. The
	// only delivery implemented; an envelope mode needs its own assembler and
	// matching A verifier first.
	DeliveryTyped = "typed-payload/1"

	// TypedMax is the delivered-byte budget of every A wire schema (the whole
	// role FD content, EOF required).
	TypedMax = 4096
)

var reEnvironment = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func roleKeys(version int, extra ...string) []string {
	k := []string{"role", "source", "resource", "fd", "max_bytes"}
	if version == 3 {
		k = append(k, "payload_schema", "delivery")
	} else {
		k = append(k, "envelope")
	}
	return append(k, extra...)
}

// roleV3 checks the plan/3 per-role contract.
func roleV3(m map[string]any, r *Role) error {
	var a, b bool
	r.PayloadSchema, a = str(m["payload_schema"])
	r.Delivery, b = str(m["delivery"])
	if !a || !b || r.Delivery != DeliveryTyped {
		return Error("role_delivery")
	}
	switch r.Source {
	case "nexus":
		switch r.PayloadSchema {
		case PayloadOpaque, PayloadDBAdmin, PayloadApprovalAdmin:
		default:
			return Error("role_payload")
		}
	case "keychain-helper":
		r.HelperOutputSchema, a = str(m["helper_output_schema"])
		r.ExpectedEnvironment, b = str(m["expected_environment"])
		if !a || r.HelperOutputSchema != PayloadRuntime || r.PayloadSchema != PayloadRuntime {
			return Error("role_payload")
		}
		if !b || !reEnvironment.MatchString(r.ExpectedEnvironment) {
			return Error("role_environment")
		}
	}
	if r.PayloadSchema != PayloadOpaque && r.MaxBytes > TypedMax {
		return Error("role_fd_or_size")
	}
	return nil
}

// aExecutorRoles is the one accepted A role layout, in order.
var aExecutorRoles = []struct {
	role, source, schema string
	fd                   int64
}{
	{"approval-admin", "nexus", PayloadApprovalAdmin, 35},
	{"runtime", "keychain-helper", PayloadRuntime, 33},
	{"db-admin", "nexus", PayloadDBAdmin, 34},
}

// aExecutorProfile: exact roles/order/sources/schemas/FDs, control 36,
// enum-json output; A wire schemas appear nowhere else (checked by the
// generic branch refusing them).
func aExecutorProfile(p Plan) error {
	if len(p.Roles) != len(aExecutorRoles) || p.ControlFD != 36 || p.OutputMode != "enum-json" {
		return Error("profile_a")
	}
	for i, want := range aExecutorRoles {
		r := p.Roles[i]
		if r.Role != want.role || r.Source != want.source || r.PayloadSchema != want.schema || r.FD != want.fd || r.MaxBytes > TypedMax {
			return Error("profile_a")
		}
	}
	return nil
}

// genericProfile: the A-only db-admin and approval-admin wire schemas are
// refused outside a-executor/1 (no cross-profile substitution); generic
// Keychain helpers with runtime-wire/1 stay allowed (ruling §1).
func genericProfile(p Plan) error {
	for _, r := range p.Roles {
		if r.PayloadSchema == PayloadDBAdmin || r.PayloadSchema == PayloadApprovalAdmin {
			return Error("profile_generic")
		}
	}
	return nil
}

// ValidatePayload checks delivered bytes against a role's payload schema
// before delivery. Errors are fixed reasons; no byte, length or digest of the
// value is ever part of an error.
func ValidatePayload(r Role, b []byte) error {
	if len(b) == 0 || int64(len(b)) > r.MaxBytes {
		return Error("payload_size")
	}
	switch r.PayloadSchema {
	case PayloadOpaque:
		return nil
	case PayloadRuntime:
		m, err := strictObject(b, "environment", "runtimePassword", "version")
		if err != nil {
			return err
		}
		env, ok1 := m["environment"].(string)
		pw, ok2 := m["runtimePassword"].(string)
		if !ok1 || !ok2 || !reEnvironment.MatchString(env) || !isVersion1(m["version"]) {
			return Error("payload_runtime")
		}
		if r.ExpectedEnvironment != "" && env != r.ExpectedEnvironment {
			return Error("payload_environment")
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(pw)
		ok := err == nil && len(pw) == 43 && len(raw) == 32
		clear(raw)
		if !ok {
			return Error("payload_runtime")
		}
		return nil
	case PayloadDBAdmin:
		m, err := strictObject(b, "dbPassword", "version")
		if err != nil {
			return err
		}
		pw, ok := m["dbPassword"].(string)
		if !ok || !isVersion1(m["version"]) || len(pw) < 16 || len(pw) > 512 || !utf8.ValidString(pw) || hasControl(pw) {
			return Error("payload_db_admin")
		}
		return nil
	case PayloadApprovalAdmin:
		m, err := strictObject(b, "adminToken", "version")
		if err != nil {
			return err
		}
		tok, ok := m["adminToken"].(string)
		if !ok || !isVersion1(m["version"]) || !reAdminToken.MatchString(tok) {
			return Error("payload_approval_admin")
		}
		return nil
	}
	return Error("payload_schema")
}

var reAdminToken = regexp.MustCompile(`^[A-Za-z0-9_.-]{32,512}$`)

// loneSurrogate reports a \uD800-\uDFFF escape that is not part of a valid
// high+low pair (inside JSON strings; escapes are only meaningful there).
func loneSurrogate(b []byte) bool {
	hex4 := func(i int) (int, bool) {
		if i+6 > len(b) || b[i] != '\\' || (b[i+1] != 'u' && b[i+1] != 'U') {
			return 0, false
		}
		v := 0
		for _, c := range b[i+2 : i+6] {
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + int(c-'0')
			case c >= 'a' && c <= 'f':
				v = v*16 + int(c-'a'+10)
			case c >= 'A' && c <= 'F':
				v = v*16 + int(c-'A'+10)
			default:
				return 0, false
			}
		}
		return v, true
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			continue
		}
		if b[i+1] != 'u' {
			i++ // skip the escaped character (e.g. \\ or \")
			continue
		}
		v, ok := hex4(i)
		if !ok {
			return true
		}
		switch {
		case v >= 0xD800 && v <= 0xDBFF:
			w, ok := hex4(i + 6)
			if !ok || w < 0xDC00 || w > 0xDFFF {
				return true
			}
			i += 11
		case v >= 0xDC00 && v <= 0xDFFF:
			return true
		default:
			i += 5
		}
	}
	return false
}

func isVersion1(v any) bool {
	n, ok := v.(json.Number)
	return ok && string(n) == "1"
}

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) {
			return true
		}
	}
	return false
}

// strictObject decodes exactly one JSON object with exactly the given keys,
// no duplicates, nothing trailing (no newline either), numbers kept exact.
func strictObject(b []byte, keys ...string) (map[string]any, error) {
	bad := Error("payload_shape")
	// encoding/json would silently repair invalid UTF-8 and lone surrogate
	// escapes to U+FFFD; refuse them on the raw bytes first (P3-R1). A valid
	// surrogate pair and a genuine U+FFFD stay accepted.
	if !utf8.Valid(b) || loneSurrogate(b) {
		return nil, Error("payload_encoding")
	}
	// exact framing: the object itself, no leading/trailing bytes (no newline)
	if len(b) < 2 || b[0] != '{' || b[len(b)-1] != '}' {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, bad
	}
	m := map[string]any{}
	for d.More() {
		kt, err := d.Token()
		k, ok := kt.(string)
		if err != nil || !ok {
			return nil, bad
		}
		if _, dup := m[k]; dup {
			return nil, bad
		}
		var v any
		if d.Decode(&v) != nil {
			return nil, bad
		}
		if _, nested := v.(map[string]any); nested {
			return nil, bad
		}
		if _, nested := v.([]any); nested {
			return nil, bad
		}
		m[k] = v
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, bad
	}
	if _, err := d.Token(); err != io.EOF || d.InputOffset() != int64(len(b)) {
		return nil, bad
	}
	if len(m) != len(keys) {
		return nil, bad
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, bad
		}
	}
	return m, nil
}
