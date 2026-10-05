package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Directory layout read by the server. `newtype release publish-files`
// writes the flat form; a release publisher can use the versioned form,
// where one rename of the small "current" file
// switches manifest and signature together (docs/install-service.md):
//
//	<dir>/files/<sha256>                    content addressed, additive
//	<dir>/versions/<version>/manifest.json  immutable once written
//	<dir>/versions/<version>/manifest.sig
//	<dir>/current                           "<version>\n"; wins when present
//	<dir>/manifest.json, <dir>/manifest.sig flat form, used without "current"
const (
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.sig"
	FilesDir      = "files"
	VersionsDir   = "versions"
	CurrentFile   = "current"
	maxCurrent    = 128
)

// ValidDir reports whether dir may be used as NEXUS_RELEASES_DIR: an
// absolute, clean path without control characters.
func ValidDir(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && !strings.ContainsAny(dir, "\r\n\x00")
}

// Handler serves GET /v1/releases/latest and GET /v1/releases/files/{sha256}
// read-only from dir. An empty dir (NEXUS_RELEASES_DIR unset) answers 404 on
// both routes. The server never verifies or signs: the client checks the
// signature with its pinned key, so these routes need no authentication.
// Every path is opened through os.Root, so nothing outside dir is reachable.
func Handler(dir string) http.Handler {
	key, _ := PinnedKey()
	return handler(dir, key)
}

// handler also serves the install service (installsvc.go); key verifies the
// manifest for the install routes only (nil: no release for them).
func handler(dir string, key ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()
	installRoutes(mux, dir, key)
	mux.HandleFunc("GET /v1/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		root, ok := openRoot(w, dir)
		if !ok {
			return
		}
		defer root.Close()
		manifest, rawSig, err := readLatest(root)
		if errors.Is(err, errLayout) {
			unavailable(w)
			return
		}
		if err != nil {
			notFound(w)
			return
		}
		body, err := json.Marshal(Envelope{Manifest: base64.StdEncoding.EncodeToString(manifest), Signature: base64.StdEncoding.EncodeToString(rawSig)})
		if err != nil {
			unavailable(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Short: a new release should reach clients within minutes.
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /v1/releases/files/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		sum := r.PathValue("sha256")
		if !ValidSHA256(sum) {
			notFound(w)
			return
		}
		root, ok := openRoot(w, dir)
		if !ok {
			return
		}
		defer root.Close()
		f, err := root.Open(FilesDir + "/" + sum)
		if err != nil {
			notFound(w)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > MaxArtifactBytes {
			notFound(w)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// Content addressed: the bytes for a digest never change.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", `"`+sum+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, "", st.ModTime(), f)
	})
	mux.HandleFunc("/v1/releases/", func(w http.ResponseWriter, r *http.Request) { notFound(w) })
	return mux
}

// Mount routes /v1/releases/ and the install service paths (/llm.txt,
// /llms.txt, /install.sh, /install.ps1) to Handler(dir) and everything else
// to next.
func Mount(next http.Handler, dir string) http.Handler {
	key, _ := PinnedKey()
	return mount(next, dir, key)
}

func mount(next http.Handler, dir string, key ed25519.PublicKey) http.Handler {
	releases := handler(dir, key)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/releases" || strings.HasPrefix(r.URL.Path, "/v1/releases/") || installPaths[r.URL.Path] {
			releases.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func openRoot(w http.ResponseWriter, dir string) (*os.Root, bool) {
	root, err := openRootDir(dir)
	if err != nil {
		notFound(w)
		return nil, false
	}
	return root, true
}

func openRootDir(dir string) (*os.Root, error) {
	if dir == "" || !ValidDir(dir) {
		return nil, fs.ErrNotExist
	}
	return os.OpenRoot(dir)
}

var (
	errTooLarge = errors.New("release: file over bound")
	errLayout   = errors.New("release: inconsistent release directory")
)

// readLatest returns the published manifest bytes and decoded signature.
// With a "current" file both come from versions/<current>/, a directory that
// is never rewritten, so a reader never pairs one release's manifest with
// another's signature. A missing release is fs.ErrNotExist; a malformed
// pointer or signature is errLayout.
func readLatest(root *os.Root) (manifest, sig []byte, err error) {
	dir := root
	ptr, err := readBounded(root, CurrentFile, maxCurrent)
	switch {
	case err == nil:
		v := strings.TrimSuffix(string(ptr), "\n")
		if !ValidVersion(v) || strings.ContainsAny(v, "/\\") {
			return nil, nil, errLayout
		}
		sub, err := root.OpenRoot(VersionsDir + "/" + v)
		if err != nil {
			return nil, nil, errLayout
		}
		defer sub.Close()
		dir = sub
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, errLayout
	}
	manifest, err1 := readBounded(dir, ManifestFile, MaxManifestBytes)
	rawSig, err2 := readBounded(dir, SignatureFile, MaxSignatureBytes)
	if err1 != nil || err2 != nil {
		if dir != root {
			return nil, nil, errLayout
		}
		return nil, nil, fs.ErrNotExist
	}
	if sig, err = DecodeSignature(rawSig); err != nil {
		return nil, nil, errLayout
	}
	return manifest, sig, nil
}

func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit || len(raw) == 0 {
		return nil, errTooLarge
	}
	return raw, nil
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"not_found"}`))
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"unavailable"}`))
}
