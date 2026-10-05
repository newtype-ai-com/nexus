package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testKey is a placeholder generated per test run; never a production key.
func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func manifestFor(version string, bins map[string][]byte) Manifest {
	m := Manifest{Version: version, ReleasedAt: "2026-10-04T12:00:00Z", Notes: "test release"}
	for platform, b := range bins {
		goos, goarch, _ := strings.Cut(platform, "/")
		m.Artifacts = append(m.Artifacts, Artifact{OS: goos, Arch: goarch, Path: "newtype-" + goos + "-" + goarch, Size: int64(len(b)), SHA256: digest(b)})
	}
	return m
}

// publish writes the server directory layout.
func publish(t *testing.T, priv ed25519.PrivateKey, m Manifest, bins map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, raw)
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(dir, ManifestFile), raw, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, SignatureFile), EncodeSignature(sig), 0o644))
	must(t, os.MkdirAll(filepath.Join(dir, FilesDir), 0o755))
	for _, b := range bins {
		must(t, os.WriteFile(filepath.Join(dir, FilesDir, digest(b)), b, 0o644))
	}
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestManifestCanonicalSignVerify(t *testing.T) {
	pub, priv := testKey(t)
	m := manifestFor("20261005a", map[string][]byte{"darwin/arm64": []byte("bin")})
	raw, err := Canonical(m)
	must(t, err)
	sig, err := Sign(priv, raw)
	must(t, err)
	got, err := Verify(pub, raw, sig)
	if err != nil || got.Version != "20261005a" {
		t.Fatalf("verify: %v %+v", err, got)
	}
	// Any byte change, other key, or pretty-printed form is refused.
	tampered := bytes.Replace(raw, []byte("20261005a"), []byte("20261005b"), 1)
	if _, err := Verify(pub, tampered, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
	other, _ := testKey(t)
	if _, err := Verify(other, raw, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := Verify(nil, raw, sig); !errors.Is(err, ErrDisabled) {
		t.Fatalf("no key: %v", err)
	}
	pretty, _ := json.MarshalIndent(m, "", " ")
	if _, err := Sign(priv, pretty); !errors.Is(err, ErrManifest) {
		t.Fatalf("non-canonical sign: %v", err)
	}
	// A signature from a different context (raw manifest without prefix) fails.
	if _, err := Verify(pub, raw, ed25519.Sign(priv, raw)); !errors.Is(err, ErrSignature) {
		t.Fatalf("context: %v", err)
	}
}

func TestManifestValidate(t *testing.T) {
	good := manifestFor("1.2.3", map[string][]byte{"linux/arm64": []byte("x")})
	must(t, good.Validate())
	for name, mutate := range map[string]func(*Manifest){
		"version":   func(m *Manifest) { m.Version = "local-dev" },
		"time":      func(m *Manifest) { m.ReleasedAt = "yesterday" },
		"notes":     func(m *Manifest) { m.Notes = "a\x1b[31m" },
		"none":      func(m *Manifest) { m.Artifacts = nil },
		"os":        func(m *Manifest) { m.Artifacts[0].OS = "plan9" },
		"path":      func(m *Manifest) { m.Artifacts[0].Path = "../x" },
		"sha":       func(m *Manifest) { m.Artifacts[0].SHA256 = strings.ToUpper(m.Artifacts[0].SHA256) },
		"size":      func(m *Manifest) { m.Artifacts[0].Size = MaxArtifactBytes + 1 },
		"duplicate": func(m *Manifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[0]) },
	} {
		m := good
		m.Artifacts = append([]Artifact(nil), good.Artifacts...)
		mutate(&m)
		if m.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseManifest([]byte(`{"version":"1.2.3","released_at":"2026-10-04T12:00:00Z","notes":"","artifacts":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"20261004e", "20261004d", 1},
		{"20261004d", "20261004d", 0},
		{"20261004a", "20261004", 1},
		{"20261005", "20261004z", 1},
		{"0.4.21", "0.4.3", 1},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-rc2", "1.0.0-rc10", -1},
		{"1.10", "1.9", 1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestHandlerServesLatestAndFiles(t *testing.T) {
	pub, priv := testKey(t)
	bin := []byte("new binary bytes")
	m := manifestFor("20261005a", map[string][]byte{"darwin/arm64": bin})
	dir := publish(t, priv, m, map[string][]byte{"darwin/arm64": bin})
	srv := httptest.NewServer(Mount(http.NotFoundHandler(), dir))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/releases/latest")
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("latest: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	var env Envelope
	must(t, json.Unmarshal(body, &env))
	raw, _ := base64.StdEncoding.DecodeString(env.Manifest)
	sig, _ := base64.StdEncoding.DecodeString(env.Signature)
	if _, err := Verify(pub, raw, sig); err != nil {
		t.Fatalf("served envelope does not verify: %v", err)
	}

	resp, err = http.Get(srv.URL + "/v1/releases/files/" + digest(bin))
	must(t, err)
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, bin) || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") || resp.Header.Get("ETag") != `"`+digest(bin)+`"` {
		t.Fatalf("file: %d %q", resp.StatusCode, resp.Header)
	}

	for _, path := range []string{
		"/v1/releases/files/" + strings.Repeat("0", 64),
		"/v1/releases/files/" + strings.ToUpper(digest(bin)),
		"/v1/releases/files/..%2fmanifest.json",
		"/v1/releases/files/../manifest.json",
		"/v1/releases/manifest.json",
		"/v1/releases/files/",
	} {
		resp, err := http.Get(srv.URL + path)
		must(t, err)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/releases/latest", nil)
	resp, err = http.DefaultClient.Do(req)
	must(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}

func TestHandlerUnsetOrUnsafe(t *testing.T) {
	outside := t.TempDir()
	secret := []byte("outside the release dir")
	must(t, os.WriteFile(filepath.Join(outside, "secret"), secret, 0o644))
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, FilesDir), 0o755))
	// A symlink out of the directory is refused by os.Root.
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, FilesDir, digest(secret))); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks needs Developer Mode or elevation on Windows: %v", err)
		}
		t.Fatal(err)
	}
	must(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, ManifestFile)))
	big := bytes.Repeat([]byte("x"), MaxSignatureBytes+1)
	must(t, os.WriteFile(filepath.Join(dir, SignatureFile), big, 0o644))
	for _, d := range []string{"", "relative/dir", dir} {
		h := Mount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }), d)
		for _, path := range []string{"/v1/releases/latest", "/v1/releases/files/" + digest(secret)} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != 404 || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("dir %q %s: %d", d, path, rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
		if rec.Code != 299 {
			t.Errorf("other routes must pass through: %d", rec.Code)
		}
	}
}

func TestPinnedKeyIsAValidKey(t *testing.T) {
	if ReleasePublicKey == "" {
		t.Skip("no production key pinned")
	}
	if k, err := PinnedKey(); err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatalf("pinned key: %v (%d bytes)", err, len(k))
	}
}

func TestPinnedKeyFailsClosedWhileUnset(t *testing.T) {
	if ReleasePublicKey != "" {
		t.Skip("production key pinned")
	}
	if _, err := PinnedKey(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("unset key: %v", err)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".newtype-") {
			t.Errorf("leftover %s", e.Name())
		}
	}
}
