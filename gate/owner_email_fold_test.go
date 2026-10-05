package gate

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// L7: owner checks compare trimmed, ASCII-lowercased addresses with ==, so
// Unicode case-folding lookalikes never match the owner.
func TestSameEmailRefusesUnicodeFolds(t *testing.T) {
	for _, ok := range [][2]string{{"boss@selfhost.test", "boss@selfhost.test"}, {"Boss@SelfHost.TEST", "boss@selfhost.test"}, {" boss@selfhost.test ", "boss@selfhost.test"}, {UserAdministrator, UserAdministrator}} {
		if !SameEmail(ok[0], ok[1]) {
			t.Fatalf("%q != %q", ok[0], ok[1])
		}
	}
	for _, bad := range []string{"boſs@selfhost.test", "boss@selfhost.teſt", "Kboss@selfhost.test", "", " "} {
		if SameEmail(bad, "boss@selfhost.test") || SameEmail(bad, bad) && !isASCII(bad) {
			t.Fatalf("%q matched", bad)
		}
	}
	if SameEmail("", "") {
		t.Fatal("empty matched")
	}
	if validEmail("boſs@selfhost.test") {
		t.Fatal("non-ASCII address valid")
	}
}

func TestOwnerPersonRefusesLongS(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	creds := NewMemoryCredentials()
	seat := func(email, c string) (string, string) {
		account := ids.Account(ids.New(ids.KindAccount))
		key, login := "ntl_"+strings.Repeat(c, 64), "ntg_"+strings.Repeat(c, 64)
		for token, kind := range map[string]string{key: "licence", login: "login"} {
			if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: email, Expires: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
		return key, login
	}
	owner := func(key, login string) bool {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		_, ok := OwnerPerson(r, creds, "boss@selfhost.test", now)
		return ok
	}
	if k, l := seat("boſs@selfhost.test", "a"); owner(k, l) {
		t.Fatal("long-s lookalike treated as owner")
	}
	if k, l := seat("Boss@SelfHost.test", "b"); !owner(k, l) {
		t.Fatal("case variant of the owner refused")
	}
}
