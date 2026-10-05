// Package release is the signed client self-update path (docs/client-self-update.md).
//
// The trust anchor is an Ed25519 signature made offline by the operator over
// the exact manifest.json bytes; TLS, Cloudflare and the Nexus server are only
// transport. The client verifies the signature with a key pinned in the
// binary, then checks every downloaded artifact against the signed size and
// SHA-256 before anything on disk changes.
package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// ReleasePublicKey is the pinned release signing key (standard base64 of the
// 32-byte Ed25519 public key printed once by `newtype release keygen`). The
// private key is held offline by the release operator. There is no fallback key and no way to supply one at run time.
const ReleasePublicKey = "4NmGUtYapD39KAuB/MzVSoj0onAGbS5YN0cwqFv8wMI="

// Bounds shared by the server and the client.
const (
	MaxManifestBytes  = 64 << 10
	MaxSignatureBytes = 256
	MaxArtifactBytes  = 256 << 20
	maxNotes          = 500
	maxArtifacts      = 16
)

// signingContext separates release signatures from any other use of the key.
const signingContext = "newtype-release-manifest-v1\x00"

var (
	ErrDisabled  = errors.New("release: update disabled (no pinned release key)")
	ErrManifest  = errors.New("release: invalid manifest")
	ErrSignature = errors.New("release: manifest signature invalid")
	ErrNoBuild   = errors.New("release: no artifact for this platform")
)

// Manifest is the signed release description. Its canonical encoding is
// json.Marshal of this struct (field order as declared, no spaces, no
// trailing newline); ParseManifest refuses any other byte form.
type Manifest struct {
	Version    string     `json:"version"`
	ReleasedAt string     `json:"released_at"`
	Notes      string     `json:"notes"`
	Artifacts  []Artifact `json:"artifacts"`
}

// Artifact is one platform binary. Path is a plain file name (the operator's
// build output next to manifest.json); the server addresses it by SHA256.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var (
	reVersion = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.\-]{0,63}$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePath    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._\-]{0,127}$`)
)

// ValidVersion reports whether v is a release version string. "local-dev"
// and other non-numeric builds are not.
func ValidVersion(v string) bool { return reVersion.MatchString(v) }

// ValidSHA256 reports a lowercase hex SHA-256 digest.
func ValidSHA256(s string) bool { return reSHA256.MatchString(s) }

// Validate checks every field against fixed bounds.
func (m Manifest) Validate() error {
	if !ValidVersion(m.Version) {
		return ErrManifest
	}
	if t, err := time.Parse(time.RFC3339, m.ReleasedAt); err != nil || t.IsZero() {
		return ErrManifest
	}
	if len(m.Notes) > maxNotes || strings.ContainsFunc(m.Notes, func(r rune) bool { return r != '\n' && unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return ErrManifest
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > maxArtifacts {
		return ErrManifest
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		key := a.OS + "/" + a.Arch
		if seen[key] || !knownPlatform(a.OS, a.Arch) || !rePath.MatchString(a.Path) || a.Size <= 0 || a.Size > MaxArtifactBytes || !ValidSHA256(a.SHA256) {
			return ErrManifest
		}
		seen[key] = true
	}
	return nil
}

func knownPlatform(goos, goarch string) bool {
	switch goos {
	case "darwin", "linux", "windows":
	default:
		return false
	}
	return goarch == "amd64" || goarch == "arm64"
}

// Canonical returns the only accepted byte form of a valid manifest.
func Canonical(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// ParseManifest decodes strictly (no unknown fields, no trailing data) and
// requires raw to be the canonical encoding.
func ParseManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return Manifest{}, ErrManifest
	}
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return Manifest{}, ErrManifest
	}
	canonical, err := Canonical(m)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Manifest{}, ErrManifest
	}
	return m, nil
}

// For returns the artifact for one platform.
func (m Manifest) For(goos, goarch string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, nil
		}
	}
	return Artifact{}, ErrNoBuild
}

func signedMessage(manifest []byte) []byte {
	return append([]byte(signingContext), manifest...)
}

// Sign signs canonical manifest bytes.
func Sign(key ed25519.PrivateKey, manifest []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	if _, err := ParseManifest(manifest); err != nil {
		return nil, err
	}
	return ed25519.Sign(key, signedMessage(manifest)), nil
}

// Verify checks the signature over the exact bytes first and only then
// parses them. An empty or malformed key fails closed.
func Verify(pub ed25519.PublicKey, manifest, sig []byte) (Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Manifest{}, ErrDisabled
	}
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes || len(sig) != ed25519.SignatureSize {
		return Manifest{}, ErrSignature
	}
	if !ed25519.Verify(pub, signedMessage(manifest), sig) {
		return Manifest{}, ErrSignature
	}
	return ParseManifest(manifest)
}

// PinnedKey returns the compiled-in release key, or ErrDisabled.
func PinnedKey() (ed25519.PublicKey, error) { return ParsePublicKey(ReleasePublicKey) }

// ParsePublicKey decodes a standard-base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrDisabled
	}
	return ed25519.PublicKey(raw), nil
}

// EncodeSignature is the manifest.sig file form: base64 and one newline.
func EncodeSignature(sig []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// DecodeSignature accepts the manifest.sig file form.
func DecodeSignature(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxSignatureBytes {
		return nil, ErrSignature
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(raw), "\n"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	return sig, nil
}

// Envelope is the GET /v1/releases/latest body: both files, base64 encoded
// so the signed bytes arrive exactly as written.
type Envelope struct {
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

// Compare orders release versions: -1 when a is older than b, 0 equal, 1
// newer. The part before the first '-' is compared as runs of digits
// (numerically) and letters (lexically), ignoring '.', so both 0.4.21 and
// date builds such as 20261004d order naturally; a '-' suffix marks a
// pre-release, older than the same version without one.
func Compare(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	ac, ap, aPre := strings.Cut(a, "-")
	bc, bp, bPre := strings.Cut(b, "-")
	if c := natural(ac, bc); c != 0 {
		return c
	}
	switch {
	case aPre && !bPre:
		return -1
	case !aPre && bPre:
		return 1
	}
	return natural(ap, bp)
}

func natural(a, b string) int {
	as, bs := runs(a), runs(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := as[i], bs[i]
		xd, yd := isDigits(x), isDigits(y)
		switch {
		case xd && yd:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return sign(len(x) - len(y))
			}
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		case xd != yd:
			// A number sorts after a letter run at the same position.
			if xd {
				return 1
			}
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return sign(len(as) - len(bs))
}

func runs(s string) []string {
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	for _, r := range s {
		switch {
		case r == '.' || r == '-':
			flush()
		case cur != "" && isDigits(cur) != unicode.IsDigit(r):
			flush()
			cur = string(r)
		default:
			cur += string(r)
		}
	}
	flush()
	return out
}

func isDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
