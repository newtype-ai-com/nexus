package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestInstallRoutesContentAndHeaders(t *testing.T) {
	pub, priv := testKey(t)
	bins := map[string][]byte{"darwin/arm64": []byte("mac arm"), "linux/amd64": []byte("linux amd"), "windows/amd64": []byte("win amd")}
	m := manifestFor("0.20261005.1", bins)
	dir := publish(t, priv, m, bins)
	h := mount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }), dir, pub)

	for _, path := range []string{"/llm.txt", "/llms.txt", "/install.sh", "/install.ps1", "/v1/releases/latest.txt"} {
		rec := get(t, h, path)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Header().Get("Cache-Control") != "public, max-age=300" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s headers %v", path, rec.Header())
		}
		body := rec.Body.String()
		// No secret or server detail: not the directory, not key material.
		for _, bad := range []string{dir, base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(priv.Seed()), "NEXUS_", "SEAL_MASTER", "DATABASE_URL", "Bearer "} {
			if strings.Contains(body, bad) {
				t.Errorf("%s leaks %q", path, bad)
			}
		}
	}
	if rec := get(t, h, "/install.sh"); rec.Body.String() != InstallScript("install.sh") {
		t.Error("install.sh body differs from the embedded script")
	}
	if rec := get(t, h, "/install.ps1"); rec.Body.String() != InstallScript("install.ps1") {
		t.Error("install.ps1 body differs from the embedded script")
	}

	llm := get(t, h, "/llm.txt").Body.String()
	if get(t, h, "/llms.txt").Body.String() != llm {
		t.Error("/llms.txt differs from /llm.txt")
	}
	for _, want := range []string{
		"curl -fsSL https://lic.newtype-ai.com/install.sh | sh",
		"irm https://lic.newtype-ai.com/install.ps1 | iex",
		"newtype --version",
		"version: 0.20261005.1",
		"sha256 darwin-arm64: " + digest(bins["darwin/arm64"]),
		"sha256 windows-amd64: " + digest(bins["windows/amd64"]),
		"STOP after installing",
		"e-mail enrolment",
		"NEVER type, ask for, read or",
		"newtype nmcp setup claude --channel --apply",
		"claude mcp add --transport http nexus https://lic.newtype-ai.com/mcp",
		"newtype update",
		"Ed25519",
		"Authenticode-unsigned",
		"Smart App Control may block",
		"Do NOT bypass",
		"사람에게",
		"%USERPROFILE%\\.local\\bin\\newtype.exe",
		"packaged (MSIX) app such as the Claude desktop app",
		"their own PowerShell",
		"## Run your own Nexus (self-host)",
		"https://github.com/newtype-ai-com/nexus",
		"docker compose run --rm nexus migrate",
		"curl -fsS http://127.0.0.1:8080/v1/health",
		"newtype auth enrol --gate-url https://<your-domain>",
		"claude mcp add --transport http nexus https://<your-domain>/mcp",
		"STOP: the PERSON fills .env",
		"never generate,",
		"owner's first enrolment approval",
		"docker compose run --rm enrol-owner",
		"off by default in the server",
		"set it to 0 after the owner has enrolled",
		"newtype auth enrol --gate-url https://<your-domain> --code\n",
		"STOP: this opens public ports 80",
		"plain http only on 127.0.0.1",
		"POST /mcp answers 401 without a token",
	} {
		if !strings.Contains(llm, want) {
			t.Errorf("llm.txt missing %q", want)
		}
	}

	latest := get(t, h, "/v1/releases/latest.txt").Body.String()
	want := "version=0.20261005.1\nreleased_at=2026-10-04T12:00:00Z\n" +
		"darwin-arm64=" + digest(bins["darwin/arm64"]) + " 7\n" +
		"linux-amd64=" + digest(bins["linux/amd64"]) + " 9\n" +
		"windows-amd64=" + digest(bins["windows/amd64"]) + " 7\n"
	if !strings.HasSuffix(latest, want) {
		t.Errorf("latest.txt:\n%s", latest)
	}

	// The existing JSON route still works and other paths pass through.
	if rec := get(t, h, "/v1/releases/latest"); rec.Code != 200 {
		t.Errorf("latest: %d", rec.Code)
	}
	for _, path := range []string{"/", "/llm", "/install", "/install.sh/x", "/v1/health"} {
		if rec := get(t, h, path); rec.Code != 299 {
			t.Errorf("%s not passed through: %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/install.sh", nil))
	if rec.Code == 200 {
		t.Error("POST /install.sh answered 200")
	}
}

func TestInstallRoutesWithoutRelease(t *testing.T) {
	pub, priv := testKey(t)
	other, _ := testKey(t)
	bins := map[string][]byte{"linux/arm64": []byte("x")}
	published := publish(t, priv, manifestFor("0.20261005.1", bins), bins)
	empty := t.TempDir()

	// NEXUS_RELEASES_DIR unset: every install route is 404, like the release routes.
	for _, d := range []string{"", "relative"} {
		h := mount(http.NotFoundHandler(), d, pub)
		for _, path := range []string{"/llm.txt", "/llms.txt", "/install.sh", "/install.ps1", "/v1/releases/latest.txt"} {
			if rec := get(t, h, path); rec.Code != 404 || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("dir %q %s: %d", d, path, rec.Code)
			}
		}
	}
	// Set but nothing verifiable: an empty dir, no pinned key, or another key.
	for name, h := range map[string]http.Handler{
		"empty":     mount(http.NotFoundHandler(), empty, pub),
		"no key":    mount(http.NotFoundHandler(), published, nil),
		"wrong key": mount(http.NotFoundHandler(), published, other),
	} {
		if rec := get(t, h, "/v1/releases/latest.txt"); rec.Code != 404 {
			t.Errorf("%s latest.txt: %d", name, rec.Code)
		}
		llm := get(t, h, "/llm.txt")
		if llm.Code != 200 || !strings.Contains(llm.Body.String(), "none: no signed release is published yet") || strings.Contains(llm.Body.String(), "version: ") {
			t.Errorf("%s llm.txt: %d", name, llm.Code)
		}
		if rec := get(t, h, "/install.sh"); rec.Code != 200 {
			t.Errorf("%s install.sh: %d", name, rec.Code)
		}
	}
}

// publishVersion writes the versioned layout of make_release.py.
func publishVersion(t *testing.T, dir string, priv ed25519.PrivateKey, m Manifest, bins map[string][]byte) {
	t.Helper()
	raw, err := Canonical(m)
	must(t, err)
	sig, err := Sign(priv, raw)
	must(t, err)
	vdir := filepath.Join(dir, VersionsDir, m.Version)
	must(t, os.MkdirAll(vdir, 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, FilesDir), 0o755))
	must(t, os.WriteFile(filepath.Join(vdir, ManifestFile), raw, 0o644))
	must(t, os.WriteFile(filepath.Join(vdir, SignatureFile), EncodeSignature(sig), 0o644))
	for _, b := range bins {
		must(t, os.WriteFile(filepath.Join(dir, FilesDir, digest(b)), b, 0o644))
	}
}

func TestCurrentPointerSwitchesManifestAndSignatureTogether(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	b1 := map[string][]byte{"linux/arm64": []byte("one")}
	b2 := map[string][]byte{"linux/arm64": []byte("two")}
	publishVersion(t, dir, priv, manifestFor("0.20261005.1", b1), b1)
	publishVersion(t, dir, priv, manifestFor("0.20261005.2", b2), b2)
	// A stale flat manifest is ignored once "current" exists.
	flat := publish(t, priv, manifestFor("0.20261001.1", b1), b1)
	for _, f := range []string{ManifestFile, SignatureFile} {
		raw, _ := os.ReadFile(filepath.Join(flat, f))
		must(t, os.WriteFile(filepath.Join(dir, f), raw, 0o644))
	}
	h := mount(http.NotFoundHandler(), dir, pub)
	version := func() string {
		rec := get(t, h, "/v1/releases/latest.txt")
		v, _, _ := strings.Cut(strings.SplitN(rec.Body.String(), "version=", 2)[1], "\n")
		return v
	}
	if v := version(); v != "0.20261001.1" {
		t.Fatalf("flat layout: %s", v)
	}
	for _, v := range []string{"0.20261005.1", "0.20261005.2", "0.20261005.1"} {
		must(t, os.WriteFile(filepath.Join(dir, ".current.new"), []byte(v+"\n"), 0o644))
		must(t, os.Rename(filepath.Join(dir, ".current.new"), filepath.Join(dir, CurrentFile)))
		if got := version(); got != v {
			t.Fatalf("current %s served %s", v, got)
		}
	}
	// A bad pointer is an inconsistent directory: 503 on the JSON route, no release elsewhere.
	for _, bad := range []string{"../x\n", "0.20261009.1\n", "\n", "a/b\n", strings.Repeat("1", 200)} {
		must(t, os.WriteFile(filepath.Join(dir, CurrentFile), []byte(bad), 0o644))
		if rec := get(t, h, "/v1/releases/latest"); rec.Code != 503 {
			t.Errorf("pointer %q: %d", bad, rec.Code)
		}
		if rec := get(t, h, "/v1/releases/latest.txt"); rec.Code != 404 {
			t.Errorf("pointer %q latest.txt: %d", bad, rec.Code)
		}
	}
}

func ps1Code(t *testing.T) []string {
	t.Helper()
	var code []string
	for _, line := range strings.Split(InstallScript("install.ps1"), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			code = append(code, line)
		}
	}
	return code
}

func TestInstallPS1Static(t *testing.T) {
	script := InstallScript("install.ps1")
	for i, r := range script {
		if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
			t.Fatalf("non-ASCII or control character at %d (Windows PowerShell 5.1 code pages)", i)
		}
	}
	code := strings.Join(ps1Code(t), "\n")
	// Windows PowerShell 5.1 has no pipeline chain, null-coalescing or ternary
	// operators and no ConvertFrom-Json -AsHashtable.
	for _, bad := range []string{"&&", "||", "??", "-AsHashtable"} {
		if strings.Contains(code, bad) {
			t.Errorf("PowerShell 7-only syntax %q", bad)
		}
	}
	if regexp.MustCompile(`\s\?\s`).MatchString(code) {
		t.Error("ternary operator (PowerShell 7 only)")
	}
	// Never evaluates downloaded data, never leaves the user scope, never
	// ends the caller's shell (`irm | iex` runs in it), never bypasses SAC.
	for _, bad := range []string{"Invoke-Expression", "iex", "Set-ExecutionPolicy", "RunAs", "'Machine'", "HKLM", "Unblock-File", "Add-MpPreference", "exit", "Start-Process", "-EncodedCommand", "DownloadString", "ConvertFrom-Json"} {
		if regexp.MustCompile(`(?i)(^|[^A-Za-z-])` + regexp.QuoteMeta(bad) + `($|[^A-Za-z])`).MatchString(code) {
			t.Errorf("install.ps1 code uses %q", bad)
		}
	}
	for _, want := range []string{
		"Get-FileHash -Algorithm SHA256",
		"-UseBasicParsing",
		"[Net.SecurityProtocolType]::Tls12",
		"/v1/releases/latest.txt",
		"/v1/releases/files/",
		"$env:USERPROFILE '.local\\share\\newtype\\bin'",
		"$env:USERPROFILE '.local\\bin'",
		"Join-Path $env:LOCALAPPDATA 'Newtype\\bin'",
		"removed the old $stale entry",
		"[Microsoft.Win32.RegistryValueKind]::ExpandString",
		"\"newtype-$version.exe\"",
		"'newtype.exe'",
		"OpenSubKey('Environment', $true)",
		"RegistryValueKind]::ExpandString",
		"'User')",
		"'AMD64'",
		"'ARM64'",
		"$gotSum -ne $sum",
		"$gotSize -ne $size",
		"'^([0-9a-f]{64}) ([1-9][0-9]{0,9})$'",
		"Windows: Authenticode unsigned; Smart App Control may block it",
		"Next: open a new terminal and run 'newtype'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.ps1 missing %q", want)
		}
	}
	// The hash check comes before the move into place.
	if strings.Index(script, "Get-FileHash") > strings.Index(script, "Move-Item -LiteralPath $tmp -Destination $target") {
		t.Error("install.ps1 installs before checking the hash")
	}
	if strings.Count(code, "{") != strings.Count(code, "}") || strings.Count(code, "(") != strings.Count(code, ")") {
		t.Error("unbalanced braces or parentheses")
	}
	if pwsh, err := exec.LookPath("pwsh"); err == nil {
		out, err := exec.Command(pwsh, "-NoProfile", "-Command", "$e=$null; [System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$null, [ref]$e) | Out-Null; $e.Count").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "0" {
			t.Errorf("pwsh parse: %v %s", err, out)
		}
	}
}

// --- install.sh under sh against a fake server ---

type shFixture struct {
	srv  *httptest.Server
	dir  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newShFixture(t *testing.T) *shFixture {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("install.sh is for macOS and Linux")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("install.sh needs arm64 or amd64")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	pub, priv := testKey(t)
	f := &shFixture{dir: t.TempDir(), pub: pub, priv: priv}
	f.srv = httptest.NewServer(mount(http.NotFoundHandler(), f.dir, pub))
	t.Cleanup(f.srv.Close)
	return f
}

func fakeBinary(version string) []byte {
	return []byte("#!/bin/sh\necho NEWTYPE SLAVES " + version + " >&2\n")
}

func (f *shFixture) release(t *testing.T, version string, content []byte) {
	t.Helper()
	bins := map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: content}
	publishVersion(t, f.dir, f.priv, manifestFor(version, bins), bins)
	must(t, os.WriteFile(filepath.Join(f.dir, CurrentFile), []byte(version+"\n"), 0o644))
}

func shells(t *testing.T) []string {
	var out []string
	for _, sh := range []string{"/bin/sh", "/bin/dash"} {
		if _, err := os.Stat(sh); err == nil {
			out = append(out, sh)
		}
	}
	if len(out) == 0 {
		t.Skip("no sh")
	}
	return out
}

func runInstallSH(t *testing.T, shell, origin, home string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, InstallScript("install.sh")) }))
	defer srv.Close()
	// The documented pipe form: the script arrives on stdin.
	resp, err := http.Get(srv.URL)
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	cmd := exec.Command(shell)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "NEWTYPE_INSTALL_ORIGIN=" + origin, "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallSHAgainstFakeServer(t *testing.T) {
	for _, shell := range shells(t) {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			f := newShFixture(t)
			home := t.TempDir()

			// Nothing published: non-zero exit, nothing installed.
			out, err := runInstallSH(t, shell, f.srv.URL, home)
			if err == nil || !strings.Contains(out, "no published release") {
				t.Fatalf("no release: %v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(home, ".local")); err == nil {
				t.Fatal("installed something without a release")
			}

			// First install.
			v1 := "0.20261005.1"
			f.release(t, v1, fakeBinary(v1))
			out, err = runInstallSH(t, shell, f.srv.URL, home)
			if err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			target := filepath.Join(home, ".local/share/newtype/bin/newtype-"+v1)
			link := filepath.Join(home, ".local/bin/newtype")
			if dest, _ := os.Readlink(link); dest != target {
				t.Fatalf("link %q\n%s", dest, out)
			}
			if got, _ := os.ReadFile(target); !bytes.Equal(got, fakeBinary(v1)) {
				t.Fatal("wrong bytes installed")
			}
			if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
				t.Fatalf("mode %v", st.Mode())
			}
			for _, want := range []string{"NEWTYPE SLAVES " + v1, "is not on your PATH", "Next: run 'newtype'", "first run needs you"} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}

			// A newer release: new versioned file, link repointed, old file kept.
			v2 := "0.20261005.2"
			f.release(t, v2, fakeBinary(v2))
			out, err = runInstallSH(t, shell, f.srv.URL, home)
			if err != nil {
				t.Fatalf("upgrade: %v\n%s", err, out)
			}
			if dest, _ := os.Readlink(link); dest != filepath.Join(home, ".local/share/newtype/bin/newtype-"+v2) {
				t.Fatalf("link after upgrade %q", dest)
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatal("previous version removed")
			}

			// Tampered file on the server: the SHA-256 check refuses, the link stays.
			v3 := "0.20261005.3"
			good := fakeBinary(v3)
			bins := map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: good}
			publishVersion(t, f.dir, f.priv, manifestFor(v3, bins), bins)
			evil := bytes.Replace(good, []byte("NEWTYPE"), []byte("EVILTYP"), 1)
			must(t, os.WriteFile(filepath.Join(f.dir, FilesDir, digest(good)), evil, 0o644))
			must(t, os.WriteFile(filepath.Join(f.dir, CurrentFile), []byte(v3+"\n"), 0o644))
			out, err = runInstallSH(t, shell, f.srv.URL, home)
			if err == nil || !strings.Contains(out, "SHA-256 mismatch") {
				t.Fatalf("tampered: %v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(home, ".local/share/newtype/bin/newtype-"+v3)); err == nil {
				t.Fatal("tampered file installed")
			}
			if dest, _ := os.Readlink(link); !strings.HasSuffix(dest, v2) {
				t.Fatalf("link moved to %q", dest)
			}
			assertNoTemp(t, filepath.Join(home, ".local/share/newtype/bin"))
			assertNoTemp(t, filepath.Join(home, ".local/bin"))
		})
	}
}

func TestInstallSHRefusals(t *testing.T) {
	f := newShFixture(t)
	f.release(t, "0.20261005.1", fakeBinary("0.20261005.1"))
	shell := shells(t)[0]
	home := t.TempDir()
	// A plain file at ~/.local/bin/newtype is kept aside, not deleted.
	must(t, os.MkdirAll(filepath.Join(home, ".local/bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(home, ".local/bin/newtype"), []byte("manual copy"), 0o755))
	out, err := runInstallSH(t, shell, f.srv.URL, home)
	if err != nil || !strings.Contains(out, "kept the existing") {
		t.Fatalf("%v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".local/bin/newtype.prev-*"))
	if len(matches) != 1 {
		t.Fatalf("kept file: %v", matches)
	}
	for _, origin := range []string{"http://example.com", "ftp://x", "https://a.b/;rm", "https://a.b/"} {
		out, err := runInstallSH(t, shell, origin, t.TempDir())
		if err == nil || !strings.Contains(out, "origin") {
			t.Errorf("origin %q accepted: %s", origin, out)
		}
	}
	// No build for this platform.
	other := map[string][]byte{"windows/arm64": []byte("w")}
	publishVersion(t, f.dir, f.priv, manifestFor("0.20261005.9", other), other)
	must(t, os.WriteFile(filepath.Join(f.dir, CurrentFile), []byte("0.20261005.9\n"), 0o644))
	out, err = runInstallSH(t, shell, f.srv.URL, t.TempDir())
	if err == nil || !strings.Contains(out, "has no build for") {
		t.Errorf("no build: %v %s", err, out)
	}
}

func TestInstallSHStatic(t *testing.T) {
	script := InstallScript("install.sh")
	if !strings.HasPrefix(script, "#!/bin/sh\n") || !strings.Contains(script, "\nset -eu\n") {
		t.Error("install.sh must be POSIX sh with set -eu")
	}
	var code []string
	for _, line := range strings.Split(script, "\n") {
		if trimmed := strings.TrimSpace(line); !strings.HasPrefix(trimmed, "#") {
			code = append(code, line)
		}
	}
	joined := strings.Join(code, "\n")
	for _, bad := range []string{"sudo", "eval", "source ", "[[", "$((", "local ", "function ", "| sh", "| bash"} {
		if strings.Contains(joined, bad) {
			t.Errorf("install.sh code uses %q", bad)
		}
	}
	if strings.Index(script, `[ "$got_sum" = "$sum" ]`) > strings.Index(script, `cp "$tmp/newtype"`) {
		t.Error("install.sh installs before checking the hash")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("sh -n: %v %s", err, out)
		}
	}
}
