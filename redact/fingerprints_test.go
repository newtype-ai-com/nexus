package redact

import (
	"strings"
	"testing"
)

func TestIntroduced(t *testing.T) {
	key := "sk-ant-" + strings.Repeat("a", 30)
	ntl := "ntl_" + strings.Repeat("b", 20)
	for name, c := range map[string]struct {
		before, after string
		want          bool
	}{
		"unchanged":           {"x " + key, "y " + key, false},
		"moved":               {key + "\nmid\n", "mid\n" + key + "\n", false},
		"removed":             {key, "gone", false},
		"new":                 {"x", "x " + ntl, true},
		"second copy":         {key, key + " " + key, true},
		"extended":            {ntl, ntl + "c", true},
		"hidden in overlap":   {"Bearer " + ntl, "Bearer " + ntl + ".abcdefghijklmnopqrstuvwxyz", true},
		"placeholder added":   {"x", "x [secret:openai_key]", false},
		"behind placeholder":  {"x", "x [secret:password]abcdefghijkl", true},
		"private key changed": {"-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nAAB\n-----END PRIVATE KEY-----", true},
	} {
		if got := Introduced(c.before, c.after); got != c.want {
			t.Errorf("%s: Introduced = %v, want %v", name, got, c.want)
		}
	}
	for k := range Fingerprints("x " + key) {
		if strings.Contains(k, key) || strings.Contains(k, "aaaa") {
			t.Fatal("fingerprint key carries the secret")
		}
	}
}
