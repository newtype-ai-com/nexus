package nexus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func validAction(action string, pattern bool) bool {
	if action == "" || !utf8.ValidString(action) || strings.IndexFunc(action, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	n := strings.Count(action, "*")
	return n == 0 || (pattern && n == 1 && strings.HasSuffix(action, "*"))
}
func knownScope(scope string) bool {
	switch scope {
	case "newtype:run", "session:delegate", "observe:progress", "read:transcript", "purchase", "send:internal", "send:external", "secrets:fd":
		return true
	}
	for _, prefix := range []string{"model:", "connector:"} {
		if strings.HasPrefix(scope, prefix) {
			suffix := strings.TrimPrefix(scope, prefix)
			return suffix != "" && validAction(scope, true)
		}
	}
	return false
}
func normalizeScopes(scopes []string) ([]string, error) {
	set := map[string]bool{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !knownScope(scope) {
			return nil, ErrInvalid
		}
		set[scope] = true
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out, nil
}
func covers(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target || (strings.HasSuffix(scope, "*") && strings.HasPrefix(target, strings.TrimSuffix(scope, "*"))) {
			return true
		}
	}
	return false
}
func requiredScope(action string) string {
	if strings.HasPrefix(action, "tool:") {
		return "newtype:run"
	}
	// Secret FD plans: exactly these actions need secrets:fd (design v4 A1).
	if action == "exec:secret-plan" || strings.HasPrefix(action, "secret:nexus:") || strings.HasPrefix(action, "secret:keychain:") {
		return "secrets:fd"
	}
	if knownScope(action) {
		return action
	}
	return ""
}
func normalizeRules(rules []Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	seen := map[string]string{}
	for _, rule := range rules {
		rule.Action = strings.TrimSpace(rule.Action)
		if !validAction(rule.Action, true) || (rule.Effect != "auto" && rule.Effect != "ask" && rule.Effect != "deny") {
			return nil, ErrInvalid
		}
		if effect, ok := seen[rule.Action]; ok {
			if effect != rule.Effect {
				return nil, ErrInvalid
			}
			continue
		}
		seen[rule.Action] = rule.Effect
		out = append(out, rule)
	}
	return out, nil
}
func normalizeApprover(a string) (string, error) {
	switch a {
	case "", "user":
		return "user", nil
	case "parent":
		return a, nil
	default:
		return "", ErrInvalid
	}
}
func (p Policy) Hash() string {
	// nil and empty rule lists represent the same policy, including after a
	// persistence round-trip that normalizes an empty slice to nil.
	rules := p.Rules
	if rules == nil {
		rules = []Rule{}
	}
	data, _ := json.Marshal(struct {
		ID       string `json:"id"`
		Version  int    `json:"version"`
		Rules    []Rule `json:"rules"`
		Approver string `json:"approver"`
	}{string(p.ID), p.Version, rules, p.Approver})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (p Policy) decide(action string) (string, bool) {
	effect := ""
	longest := -1
	for _, r := range p.Rules {
		if r.Action == action {
			return r.Effect, true
		}
		if strings.HasSuffix(r.Action, "*") {
			prefix := strings.TrimSuffix(r.Action, "*")
			if len(prefix) > longest && strings.HasPrefix(action, prefix) {
				longest = len(prefix)
				effect = r.Effect
			}
		}
	}
	return effect, effect != ""
}
func nonnegative(l Limits) bool {
	return l.ModelTokens >= 0 && l.RuntimeMinutes >= 0 && l.SubSessions >= 0 && l.Spend >= 0 && l.MaxDepth >= 0
}
func validLimits(l Limits) error {
	if !nonnegative(l) || (l.Spend > 0 && strings.TrimSpace(l.Currency) == "") {
		return ErrInvalid
	}
	return nil
}
func fits(a, b Limits) bool {
	return nonnegative(a) && nonnegative(b) && a.ModelTokens <= b.ModelTokens && a.RuntimeMinutes <= b.RuntimeMinutes && a.SubSessions <= b.SubSessions && a.Spend <= b.Spend
}

// Arithmetic ignores currency and depth: they are metadata validated by the
// caller, not consumable quantities. Check BEFORE addition to prevent overflow.
func addLimits(a, b Limits) (Limits, error) {
	if !nonnegative(a) || !nonnegative(b) {
		return Limits{}, ErrInvalid
	}
	if b.ModelTokens > math.MaxInt64-a.ModelTokens || b.RuntimeMinutes > math.MaxInt64-a.RuntimeMinutes || b.SubSessions > math.MaxInt64-a.SubSessions || b.Spend > math.MaxInt64-a.Spend {
		return Limits{}, ErrLimit
	}
	a.ModelTokens += b.ModelTokens
	a.RuntimeMinutes += b.RuntimeMinutes
	a.SubSessions += b.SubSessions
	a.Spend += b.Spend
	return a, nil
}
func subLimits(a, b Limits) (Limits, error) {
	if !fits(b, a) {
		return Limits{}, ErrConflict
	}
	a.ModelTokens -= b.ModelTokens
	a.RuntimeMinutes -= b.RuntimeMinutes
	a.SubSessions -= b.SubSessions
	a.Spend -= b.Spend
	return a, nil
}
func remaining(l Limits, u Usage) (Limits, error) {
	left, err := subLimits(l, u.Consumed)
	if err != nil {
		return Limits{}, err
	}
	return subLimits(left, u.Reserved)
}
