package nexus

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
)

func TestRulesAndScopes(t *testing.T) {
	got, err := normalizeScopes([]string{" model:* ", "newtype:run", "model:*"})
	if err != nil || !reflect.DeepEqual(got, []string{"model:*", "newtype:run"}) {
		t.Fatal(got, err)
	}
	for _, s := range []string{"", "unknown", "model:", "model:**", "model:x*y", "connector: bad", "*"} {
		if _, err := normalizeScopes([]string{s}); !errors.Is(err, ErrInvalid) {
			t.Fatal(s, err)
		}
	}
	for _, tc := range []struct {
		scope, target string
		want          bool
	}{{"model:*", "model:x", true}, {"model:x", "model:*", false}, {"model:gpt-*", "model:gpt-x", true}, {"model:gpt-x", "model:gpt-y", false}, {"model:*", "connector:x", false}} {
		if covers([]string{tc.scope}, tc.target) != tc.want {
			t.Fatal(tc)
		}
	}
	for _, tc := range []struct{ action, scope string }{{"tool:read_file", "newtype:run"}, {"purchase", "purchase"}, {"session:delegate", "session:delegate"}, {"model:x", "model:x"}, {"secret:key", ""}} {
		if requiredScope(tc.action) != tc.scope {
			t.Fatal(tc)
		}
	}
	rules, err := normalizeRules([]Rule{{"tool:*", "deny"}, {"tool:read*", "ask"}, {"tool:read_file", "auto"}, {"tool:*", "deny"}})
	if err != nil || len(rules) != 3 {
		t.Fatal(rules, err)
	}
	p := Policy{Rules: rules}
	for _, tc := range []struct {
		action, effect string
		mentioned      bool
	}{{"tool:read_file", "auto", true}, {"tool:read_dir", "ask", true}, {"tool:shell", "deny", true}, {"purchase", "", false}} {
		effect, mentioned := p.decide(tc.action)
		if effect != tc.effect || mentioned != tc.mentioned {
			t.Fatal(tc, effect, mentioned)
		}
	}
	for _, rules := range [][]Rule{{{"tool:*", "auto"}, {"tool:*", "deny"}}, {{"", "auto"}}, {{"x", "allow"}}, {{"x*y", "auto"}}, {{"x y", "auto"}}} {
		if _, err := normalizeRules(rules); !errors.Is(err, ErrInvalid) {
			t.Fatal(rules, err)
		}
	}
	for _, action := range []string{"", "model:*", "tool:read\nfile", "a b", string([]byte{0xff})} {
		if validAction(action, false) {
			t.Fatal(action)
		}
	}
	p.ID = ids.Policy("pol_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	p.Version = 1
	p.Approver = "user"
	hash := p.Hash()
	p.AccountID = "another-account"
	if p.Hash() != hash {
		t.Fatal("account unexpectedly included in hash")
	}
	p.Rules[0].Effect = "auto"
	if p.Hash() == hash {
		t.Fatal("policy content not hashed")
	}
}
func TestLimitsNoOverflow(t *testing.T) {
	for _, field := range []func(*Limits, int64){func(l *Limits, n int64) { l.ModelTokens = n }, func(l *Limits, n int64) { l.RuntimeMinutes = n }, func(l *Limits, n int64) { l.SubSessions = n }, func(l *Limits, n int64) { l.Spend = n }} {
		a, b := Limits{}, Limits{}
		field(&a, math.MaxInt64)
		field(&b, 1)
		if _, err := addLimits(a, b); !errors.Is(err, ErrLimit) {
			t.Fatal(a, b, err)
		}
		if _, err := subLimits(Limits{}, b); !errors.Is(err, ErrConflict) {
			t.Fatal(b, err)
		}
		field(&b, -1)
		if validLimits(b) == nil {
			t.Fatal(b)
		}
	}
	a := Limits{ModelTokens: 10, Spend: 10, Currency: "USD", MaxDepth: 3}
	b := Limits{ModelTokens: 3, Spend: 2, MaxDepth: 1}
	left, err := remaining(a, Usage{Consumed: b, Reserved: b})
	if err != nil || left.ModelTokens != 4 || left.Spend != 6 || left.MaxDepth != 3 || left.Currency != "USD" {
		t.Fatal(left, err)
	}
	if err := validLimits(Limits{Spend: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := remaining(Limits{ModelTokens: 1}, Usage{Consumed: Limits{ModelTokens: 1}, Reserved: Limits{ModelTokens: 1}}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
