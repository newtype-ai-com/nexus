package seal_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/seal"
)

func TestDocument13Vectors(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	d, err := seal.NewMasterDeriver(master)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ info, want string }{
		{"newtype-seal/v1|mnd_test|slv_test", "a5b008ea3b5a1da3fde13a8ca93d169196c5947d6090851a1bad4d5e24ec0cae"},
		{"newtype-secret/v1|TEST_KEY", "802c2c1c7e9ec5c018c9d7ad825390b0cdc646038aff9a924bc6cd4a00bd3849"},
	} {
		key, kid, err := d.Derive(context.Background(), "nt_test", []byte(tt.info))
		if err != nil || hex.EncodeToString(key) != tt.want || kid != "acct_0872777e2068" {
			t.Fatal("document 13 vector mismatch")
		}
	}
	prk, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	if hex.EncodeToString(seal.Expand(prk, info)) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" {
		t.Fatal("RFC5869 mismatch")
	}
}

func TestRoundTripIsolationAndMutation(t *testing.T) {
	ctx := context.Background()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := seal.NewEd25519Signer(key, "fixture-v1")
	d, _ := seal.NewMasterDeriver(bytes.Repeat([]byte{42}, 32))
	s := &seal.Sealer{Signer: signer, Deriver: d}
	payload := []byte(`{"email":"owner@example.test","v":"newtype.delegation/2"}`)
	x, err := s.Seal(ctx, "acct", "mnd", "slv", payload)
	if err != nil {
		t.Fatal(err)
	}
	jws, kid, err := seal.Open(x.Sealed, x.Key)
	if err != nil || kid != x.KID+":mnd:slv" {
		t.Fatal("open failed")
	}
	plain, err := seal.Verify(jws, signer.Keys())
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatal("verify failed")
	}
	if strings.Contains(x.Sealed, "owner") || strings.Contains(x.Sealed, "newtype.delegation") {
		t.Fatal("plaintext leak")
	}
	y, _ := s.Seal(ctx, "acct", "mnd", "slv", payload)
	if x.Sealed == y.Sealed || !bytes.Equal(x.Key, y.Key) || x.KID != y.KID {
		t.Fatal("nonce or deterministic derivation")
	}
	for _, v := range [][3]string{{"acct2", "mnd", "slv"}, {"acct", "mnd2", "slv"}, {"acct", "mnd", "slv2"}} {
		other, err := s.Seal(ctx, v[0], v[1], v[2], payload)
		if err != nil || bytes.Equal(other.Key, x.Key) {
			t.Fatal("isolation failed")
		}
		if _, _, err = seal.Open(x.Sealed, other.Key); !errors.Is(err, seal.ErrOpen) {
			t.Fatal("cross-key open")
		}
	}
	for i := 0; i < 5; i++ {
		parts := strings.Split(x.Sealed, ".")
		if i == 1 {
			parts[i] = "AA"
		} else {
			j := len(parts[i]) / 2
			b := byte('A')
			if parts[i][j] == b {
				b = 'B'
			}
			parts[i] = parts[i][:j] + string(b) + parts[i][j+1:]
		}
		if _, _, err := seal.Open(strings.Join(parts, "."), x.Key); !errors.Is(err, seal.ErrOpen) {
			t.Fatalf("accepted mutated segment %d", i)
		}
	}
	parts := strings.Split(jws, ".")
	parts[1] = "e30"
	if _, err := seal.Verify(strings.Join(parts, "."), signer.Keys()); !errors.Is(err, seal.ErrOpen) {
		t.Fatal("payload substitution")
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner, _ := seal.NewEd25519Signer(wrong, "fixture-v1")
	if _, err := seal.Verify(jws, wrongSigner.Keys()); !errors.Is(err, seal.ErrOpen) {
		t.Fatal("wrong signer")
	}
	if _, err := seal.Verify(jws, append(signer.Keys(), signer.Keys()...)); !errors.Is(err, seal.ErrOpen) {
		t.Fatal("ambiguous kid")
	}
	for _, value := range []string{x.Sealed + "\n", strings.Replace(x.Sealed, "..", ".\n.", 1)} {
		if _, _, err := seal.Open(value, x.Key); !errors.Is(err, seal.ErrOpen) {
			t.Fatal("noncanonical encoding accepted")
		}
	}
}

func FuzzOpen(f *testing.F) {
	f.Add("a..b.c.d", []byte("short"))
	f.Fuzz(func(t *testing.T, value string, key []byte) { _, _, _ = seal.Open(value, key) })
}
