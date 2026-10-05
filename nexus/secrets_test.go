package nexus

import (
	"bytes"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
)

// The AAD binds account, name and version: a ciphertext moved to another
// account, name or generation never opens.
func TestSecretAADBinding(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	acct := ids.Account(ids.New(ids.KindAccount))
	plain := []byte("PUBLIC-FIXTURE-VALUE")
	ct, err := sealSecret(key, secretAAD(acct, "DB", 2), plain)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openSecret(key, secretAAD(acct, "DB", 2), ct); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("roundtrip")
	}
	other := ids.Account(ids.New(ids.KindAccount))
	for _, aad := range [][]byte{secretAAD(acct, "DB", 1), secretAAD(acct, "DB", 3), secretAAD(acct, "DBX", 2), secretAAD(other, "DB", 2)} {
		if _, err := openSecret(key, aad, ct); err != ErrConflict {
			t.Fatalf("opened under %s", aad)
		}
	}
	flip := append([]byte(nil), ct...)
	flip[len(flip)-1] ^= 1
	if _, err := openSecret(key, secretAAD(acct, "DB", 2), flip); err != ErrConflict {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := openSecret(bytes.Repeat([]byte{8}, 32), secretAAD(acct, "DB", 2), ct); err != ErrConflict {
		t.Fatal("other key opened")
	}
	if _, err := openSecret(key, secretAAD(acct, "DB", 2), ct[:10]); err != ErrConflict {
		t.Fatal("truncated opened")
	}
}
