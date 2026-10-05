// Package secretplan parses and validates a secret plan (newtype.secret-plan/2):
// the canonical, versioned, public description of exactly one execution that
// receives secrets on file descriptors. Pure: no I/O, no clock, no network.
//
// Design: docs/nexus-secret-fd-plan-design.md (v3 + v4 amendments).
// Shared Go/Python vectors: docs/evidence/secret-plan-v2/vectors.json.
package secretplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/newtype-ai-com/nexus/ids"
)

const (
	Schema = "newtype.secret-plan/2" // legacy (envelope-labelled); removed once fixtures move to SchemaV3
	// SchemaV3 adds the consumer profile and per-role payload_schema /
	// delivery / helper_output_schema (schema ruling §1, 2026-10-04).
	SchemaV3      = "newtype.secret-plan/3"
	MaxBytes      = 64 << 10
	MaxString     = 4096
	MaxDepth      = 16
	MaxCollection = 64
	MaxInt        = int64(1) << 53
	// MaxGeneration: a Nexus secret generation is an integer in
	// [1, 2^53-1] — the exact domain JSON numbers carry losslessly in Go,
	// Python and JavaScript. It replaces design v4 A1's "positive int64"
	// (amendment A7); the secret store stops at the same bound.
	MaxGeneration = int64(1)<<53 - 1
	GenericMax    = 16384 // decision 2026-10-04: generic per-secret maximum
	EnvelopeMax   = 4096  // A bridge envelope cap (role-specific, narrower)
	MaxRoles      = 4
)

// RoleFDs is the exact role descriptor set; ControlFDs adds 36 (control only).
var (
	RoleFDs    = map[int64]bool{3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 30: true, 31: true, 32: true, 33: true, 34: true, 35: true}
	ControlFDs = map[int64]bool{3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 30: true, 31: true, 32: true, 33: true, 34: true, 35: true, 36: true}
)

// Error is a fixed reason; never input text.
type Error string

func (e Error) Error() string { return "secret plan: " + string(e) }

var (
	reSHA      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reCDHash   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reAbsChars = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	reIssuer   = regexp.MustCompile(`^https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
	reAttempt  = regexp.MustCompile(`^[a-z0-9-]{8,64}$`)
	reRole     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	reName     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	reEnum     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	reSchemaID = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}/[1-9][0-9]{0,3}$`)
	reService  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// absPath requires one canonical lexical spelling: absolute, no empty, "."
// or ".." component, no trailing separator. It is lexical only: symlinks and
// the realpath are the executor's no-follow pin checks, and same-UID
// replacement between check and use is out of scope (design v4).
func absPath(s string) bool {
	if len(s) < 2 || len(s) > 1024 || !reAbsChars.MatchString(s) {
		return false
	}
	for _, c := range strings.Split(s[1:], "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// ---- strict canonical JSON --------------------------------------------------

// Parse requires: bytes are printable ASCII only (0x20..0x7e, no \u escapes
// beyond \" and \\ are needed or accepted for non-ASCII), no duplicate keys at
// any depth, integers only within ±2^53, strings ≤4096 bytes, depth ≤16,
// collections ≤64 entries, total ≤64 KiB, and the bytes are byte-identical to
// the canonical encoding (sorted keys, no spaces).
func Parse(raw []byte) (any, error) {
	return parseBounded(raw, MaxBytes, MaxCollection)
}

// parseBounded is Parse with explicit total-size and per-collection bounds
// (the directory manifest format has its own, larger ones).
func parseBounded(raw []byte, maxBytes, maxCollection int) (any, error) {
	if len(raw) == 0 || len(raw) > maxBytes {
		return nil, Error("size")
	}
	for _, b := range raw {
		if b < 0x20 || b > 0x7e {
			return nil, Error("non_ascii")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := parse(d, 1, maxCollection)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, Error("trailing")
	}
	if !bytes.Equal(Encode(v), raw) {
		return nil, Error("not_canonical")
	}
	return v, nil
}

func parse(d *json.Decoder, depth, maxCollection int) (any, error) {
	if depth > MaxDepth {
		return nil, Error("too_deep")
	}
	t, err := d.Token()
	if err != nil {
		return nil, Error("json")
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				kt, err := d.Token()
				k, ok := kt.(string)
				if err != nil || !ok || !printable(k) || len(k) > MaxString {
					return nil, Error("key")
				}
				if _, dup := m[k]; dup {
					return nil, Error("duplicate_key")
				}
				if len(m) == maxCollection {
					return nil, Error("too_many")
				}
				if m[k], err = parse(d, depth+1, maxCollection); err != nil {
					return nil, err
				}
			}
			if _, err := d.Token(); err != nil {
				return nil, Error("json")
			}
			return m, nil
		case '[':
			out := []any{}
			for d.More() {
				if len(out) == maxCollection {
					return nil, Error("too_many")
				}
				v, err := parse(d, depth+1, maxCollection)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			if _, err := d.Token(); err != nil {
				return nil, Error("json")
			}
			return out, nil
		}
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil || n > MaxInt || n < -MaxInt || strconv.FormatInt(n, 10) != string(x) {
			return nil, Error("integer")
		}
		return n, nil
	case string:
		if !printable(x) || len(x) > MaxString {
			return nil, Error("string")
		}
		return x, nil
	case bool, nil:
		return x, nil
	}
	return nil, Error("json")
}

// printable: decoded strings are printable ASCII as well (so a "é" or
// "\u0001" escape is refused even though its bytes were ASCII).
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Encode is the canonical form for values Parse yields: sorted keys, no
// spaces, strings escaping only `"` and `\`.
func Encode(v any) []byte {
	var b bytes.Buffer
	encode(&b, v)
	return b.Bytes()
}

func encode(w *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // ASCII-only keys: byte order == code point order
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			encodeString(w, k)
			w.WriteByte(':')
			encode(w, x[k])
		}
		w.WriteByte('}')
	case []any:
		w.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				w.WriteByte(',')
			}
			encode(w, e)
		}
		w.WriteByte(']')
	case int64:
		w.WriteString(strconv.FormatInt(x, 10))
	case string:
		encodeString(w, x)
	case bool:
		w.WriteString(strconv.FormatBool(x))
	case nil:
		w.WriteString("null")
	}
}

func encodeString(w *bytes.Buffer, s string) {
	w.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			w.WriteByte('\\')
		}
		w.WriteByte(s[i])
	}
	w.WriteByte('"')
}

// Hash is "sha256:" + hex(sha256(canonical bytes)).
func Hash(raw []byte) string {
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

// ---- plan/2 -------------------------------------------------------------------

type Role struct {
	Role, Source, Resource, Envelope string
	// plan/3
	PayloadSchema, Delivery, HelperOutputSchema, ExpectedEnvironment string
	FD, MaxBytes                                                     int64
	// nexus
	Name       string
	Generation int64
	// keychain-helper
	Keychain, Service, Account string
	HelperPath, HelperSHA256   string
	HelperCDHash               string
	HelperArgv                 []string
	SchemaVersion              int64
	CustodyEvidence            string
}

type Plan struct {
	Issuer, Account, Session, Delegation, Attempt string
	Interpreter, Script                           string
	Args                                          []string
	Shim, Executor                                string
	Pins                                          map[string]string
	Cwd                                           string
	Roles                                         []Role
	ControlFD                                     int64
	OutputMode, OutputSchemaID                    string
	OutputKeys                                    map[string][]string
	Timeout, Cleanup, ExpiresAt                   int64
	Hash                                          string
	Version                                       int    // 2 or 3
	ConsumerProfile                               string // plan/3 only
	DirectoryManifests                            []DirectoryRef
	ImportPolicy                                  ImportPolicy
	CwdManifestSHA256                             string
}

func exact(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func str(v any) (string, bool)         { s, ok := v.(string); return s, ok }
func num(v any) (int64, bool)          { n, ok := v.(int64); return n, ok }
func obj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func strs(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// KeychainItemID is the first 32 hex of sha256(canonical {keychain, service, account}).
func KeychainItemID(keychain, service, account string) string {
	raw := Encode(map[string]any{"account": account, "keychain": keychain, "service": service})
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])[:32]
}

// Resource is the exact action/resource string for a role (design v4 A1).
func Resource(r Role) string {
	if r.Source == "nexus" {
		return "secret:nexus:" + r.Name
	}
	return "secret:keychain:" + KeychainItemID(r.Keychain, r.Service, r.Account)
}

// Validate parses raw and checks every plan/2 rule. Nothing is optional.
func Validate(raw []byte) (Plan, error) {
	var p Plan
	v, err := Parse(raw)
	if err != nil {
		return p, err
	}
	m, ok := obj(v)
	if !ok {
		return p, Error("keys")
	}
	topKeys := []string{"schema", "issuer", "account", "session", "delegation", "attempt", "program", "bootstrap", "pins",
		"cwd", "env", "stdin", "roles", "control_fd", "output", "timeout_seconds", "cleanup_seconds", "expires_at"}
	switch m["schema"] {
	case SchemaV3:
		p.Version = 3
		topKeys = append(topKeys, "consumer_profile", "directory_manifests", "import_policy")
	default:
		return p, Error("schema")
	}
	if !exact(m, topKeys...) {
		return p, Error("keys")
	}
	if p.Version == 3 {
		p.ConsumerProfile, ok = str(m["consumer_profile"])
		if !ok || (p.ConsumerProfile != ProfileAExecutor && p.ConsumerProfile != ProfileGeneric) {
			return p, Error("profile")
		}
	}
	p.Hash = Hash(raw)
	var ok1, ok2, ok3, ok4, ok5 bool
	p.Issuer, ok1 = str(m["issuer"])
	p.Account, ok2 = str(m["account"])
	p.Session, ok3 = str(m["session"])
	p.Delegation, ok4 = str(m["delegation"])
	p.Attempt, ok5 = str(m["attempt"])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !reIssuer.MatchString(p.Issuer) || ids.Check(ids.KindAccount, p.Account) != nil ||
		ids.Check(ids.KindSession, p.Session) != nil || ids.Check(ids.KindDelegation, p.Delegation) != nil || !reAttempt.MatchString(p.Attempt) {
		return p, Error("actor")
	}
	prog, ok := obj(m["program"])
	if !ok || !exact(prog, "interpreter", "script", "args") {
		return p, Error("program")
	}
	p.Interpreter, ok1 = str(prog["interpreter"])
	p.Script, ok2 = str(prog["script"])
	p.Args, ok3 = strs(prog["args"])
	if !ok1 || !ok2 || !ok3 || !absPath(p.Interpreter) || !absPath(p.Script) || len(p.Args) > 32 {
		return p, Error("program")
	}
	for _, a := range p.Args {
		if len(a) == 0 || len(a) > 1024 {
			return p, Error("program")
		}
	}
	boot, ok := obj(m["bootstrap"])
	if !ok || !exact(boot, "shim", "executor") {
		return p, Error("bootstrap")
	}
	p.Shim, ok1 = str(boot["shim"])
	p.Executor, ok2 = str(boot["executor"])
	if !ok1 || !ok2 || !absPath(p.Shim) || !absPath(p.Executor) {
		return p, Error("bootstrap")
	}
	pins, ok := obj(m["pins"])
	if !ok || len(pins) == 0 {
		return p, Error("pins")
	}
	p.Pins = map[string]string{}
	for path, h := range pins {
		hs, ok := str(h)
		if !absPath(path) || !ok || !reSHA.MatchString(hs) {
			return p, Error("pins")
		}
		p.Pins[path] = hs
	}
	if p.Version == 3 {
		if err := closureV3(m, &p); err != nil { // typed cwd, directory manifests, import policy
			return p, err
		}
	} else {
		p.Cwd, ok = str(m["cwd"])
		if !ok || !absPath(p.Cwd) {
			return p, Error("cwd")
		}
	}
	if env, ok := obj(m["env"]); !ok || len(env) != 0 || m["stdin"] != "devnull" {
		return p, Error("stdio")
	}
	roles, ok := m["roles"].([]any)
	if !ok || len(roles) < 1 || len(roles) > MaxRoles {
		return p, Error("roles")
	}
	seenRole, seenFD, seenRes := map[string]bool{}, map[int64]bool{}, map[string]bool{}
	for _, rv := range roles {
		r, err := role(rv, p.Version)
		if err != nil {
			return p, err
		}
		if seenRole[r.Role] || seenFD[r.FD] || seenRes[r.Resource] {
			return p, Error("role_duplicate")
		}
		seenRole[r.Role], seenFD[r.FD], seenRes[r.Resource] = true, true, true
		p.Roles = append(p.Roles, r)
	}
	p.ControlFD, ok = num(m["control_fd"])
	if !ok || !ControlFDs[p.ControlFD] || seenFD[p.ControlFD] {
		return p, Error("control_fd")
	}
	out, ok := obj(m["output"])
	if !ok || !exact(out, "mode", "schema_id", "keys") {
		return p, Error("output")
	}
	p.OutputMode, ok1 = str(out["mode"])
	p.OutputSchemaID, ok2 = str(out["schema_id"])
	keys, ok3 := obj(out["keys"])
	if !ok1 || !ok2 || !ok3 || !reSchemaID.MatchString(p.OutputSchemaID) {
		return p, Error("output")
	}
	p.OutputKeys = map[string][]string{}
	switch p.OutputMode {
	case "enum-json":
		if len(keys) == 0 {
			return p, Error("output")
		}
		for k, vals := range keys {
			list, ok := strs(vals)
			if !reEnum.MatchString(k) || !ok || len(list) == 0 {
				return p, Error("output")
			}
			seen := map[string]bool{}
			for _, e := range list {
				if !reEnum.MatchString(e) || seen[e] {
					return p, Error("output")
				}
				seen[e] = true
			}
			p.OutputKeys[k] = list
		}
	case "inherit":
		if len(keys) != 0 {
			return p, Error("output")
		}
		// the A/custody profile must report through a validated enum, never
		// inherited output (plan/2: any non-raw envelope; plan/3: a-executor/1)
		for _, r := range p.Roles {
			if p.Version == 2 && r.Envelope != "raw" {
				return p, Error("output_profile")
			}
		}
		if p.ConsumerProfile == ProfileAExecutor {
			return p, Error("output_profile")
		}
	default:
		return p, Error("output")
	}
	p.Timeout, ok1 = num(m["timeout_seconds"])
	p.Cleanup, ok2 = num(m["cleanup_seconds"])
	p.ExpiresAt, ok3 = num(m["expires_at"])
	if !ok1 || !ok2 || !ok3 || p.Timeout < 1 || p.Timeout > 600 || p.Cleanup < 1 || p.Cleanup > 30 || p.ExpiresAt < 1 {
		return p, Error("times")
	}
	switch p.ConsumerProfile {
	case ProfileAExecutor:
		if err := aExecutorProfile(p); err != nil {
			return p, err
		}
	case ProfileGeneric:
		if err := genericProfile(p); err != nil {
			return p, err
		}
	}
	// Mandatory pins: interpreter, script, shim, executor and every helper.
	need := []string{p.Interpreter, p.Script, p.Shim, p.Executor}
	for _, r := range p.Roles {
		if r.Source == "keychain-helper" {
			need = append(need, r.HelperPath)
			if p.Pins[r.HelperPath] != r.HelperSHA256 {
				return p, Error("helper_pin")
			}
		}
	}
	for _, n := range need {
		if _, ok := p.Pins[n]; !ok {
			return p, Error("pins_required")
		}
	}
	return p, nil
}

func role(v any, version int) (Role, error) {
	var r Role
	m, ok := obj(v)
	if !ok {
		return r, Error("role")
	}
	src, _ := str(m["source"])
	switch src {
	case "nexus":
		if !exact(m, roleKeys(version, "name", "generation")...) {
			return r, Error("role_keys")
		}
		r.Name, ok = str(m["name"])
		gen, okg := num(m["generation"])
		if !ok || !reName.MatchString(r.Name) || !okg || gen < 1 || gen > MaxGeneration {
			return r, Error("role_nexus")
		}
		r.Generation = gen
	case "keychain-helper":
		extra := []string{"ref", "helper", "argv", "schema", "custody_evidence_sha256"}
		if version == 3 {
			extra = append(extra, "helper_output_schema", "expected_environment")
		}
		if !exact(m, roleKeys(version, extra...)...) {
			return r, Error("role_keys")
		}
		ref, ok := obj(m["ref"])
		if !ok || !exact(ref, "keychain", "service", "account") {
			return r, Error("role_keychain")
		}
		var a, b, c bool
		r.Keychain, a = str(ref["keychain"])
		r.Service, b = str(ref["service"])
		r.Account, c = str(ref["account"])
		if !a || !b || !c || !absPath(r.Keychain) || !reService.MatchString(r.Service) || !reService.MatchString(r.Account) {
			return r, Error("role_keychain")
		}
		h, ok := obj(m["helper"])
		if !ok || !exact(h, "path", "sha256", "cdhash") {
			return r, Error("role_helper")
		}
		r.HelperPath, a = str(h["path"])
		r.HelperSHA256, b = str(h["sha256"])
		r.HelperCDHash, c = str(h["cdhash"])
		if !a || !b || !c || !absPath(r.HelperPath) || !reSHA.MatchString(r.HelperSHA256) || !reCDHash.MatchString(r.HelperCDHash) {
			return r, Error("role_helper")
		}
		r.HelperArgv, ok = strs(m["argv"])
		if !ok || len(r.HelperArgv) < 1 || r.HelperArgv[0] != r.HelperPath || len(r.HelperArgv) > 16 {
			return r, Error("role_helper")
		}
		sv, ok := num(m["schema"])
		ev, oke := str(m["custody_evidence_sha256"])
		if !ok || sv != 1 || !oke || !reSHA.MatchString(ev) {
			return r, Error("role_keychain")
		}
		r.SchemaVersion, r.CustodyEvidence = sv, ev
	default:
		return r, Error("role_source")
	}
	r.Source = src
	var a, b bool
	r.Role, a = str(m["role"])
	if !a || !reRole.MatchString(r.Role) {
		return r, Error("role")
	}
	r.FD, a = num(m["fd"])
	r.MaxBytes, b = num(m["max_bytes"])
	if !a || !RoleFDs[r.FD] || !b || r.MaxBytes < 1 || r.MaxBytes > GenericMax {
		return r, Error("role_fd_or_size")
	}
	if version == 3 {
		if err := roleV3(m, &r); err != nil {
			return r, err
		}
	} else {
		r.Envelope, b = str(m["envelope"])
		if !b || (r.Envelope != "raw" && r.Envelope != "a-bridge-envelope/1") {
			return r, Error("role")
		}
		if r.Envelope == "a-bridge-envelope/1" && r.MaxBytes > EnvelopeMax {
			return r, Error("role_fd_or_size")
		}
		if src == "keychain-helper" && r.Envelope != "a-bridge-envelope/1" {
			return r, Error("role_keychain")
		}
	}
	r.Resource, _ = str(m["resource"])
	if r.Resource != Resource(r) {
		return r, Error("resource")
	}
	return r, nil
}
