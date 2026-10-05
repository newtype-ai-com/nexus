package pgstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// BBOOT2-R6 for the Go (pgx) migrator: the assertions are on the protocol
// messages exchanged — which authentication request a server sent and whether
// any PasswordMessage followed — using a fake server that records everything
// the client sends after the startup packet.

const fixturePassword = "public-sentinel-go-scram-0123"

type fakePG struct {
	ln       net.Listener
	tlsConf  *tls.Config
	mode     string
	mu       sync.Mutex
	received []byte
	startup  bool
	done     chan struct{}
}

func auth(code uint32, extra []byte) []byte {
	b := []byte{'R', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(8+len(extra)))
	b = binary.BigEndian.AppendUint32(b, code)
	return append(b, extra...)
}

var readyForQuery = []byte{'Z', 0, 0, 0, 5, 'I'}

func newFakePG(t *testing.T, mode string, tlsConf *tls.Config) *fakePG {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{ln: ln, mode: mode, tlsConf: tlsConf, done: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() { ln.Close(); <-f.done })
	return f
}

func (f *fakePG) serve() {
	defer close(f.done)
	raw, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = raw
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if binary.BigEndian.Uint32(head[4:]) == 80877103 { // SSLRequest
		if f.tlsConf == nil {
			_, _ = c.Write([]byte{'N'})
		} else {
			_, _ = c.Write([]byte{'S'})
			tc := tls.Server(raw, f.tlsConf)
			if tc.Handshake() != nil {
				return
			}
			c = tc
		}
		if _, err := io.ReadFull(c, head[:4]); err != nil {
			return
		}
		rest := make([]byte, binary.BigEndian.Uint32(head[:4])-4)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
	} else {
		rest := make([]byte, binary.BigEndian.Uint32(head[:4])-8)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
	}
	f.mu.Lock()
	f.startup = true
	f.mu.Unlock()
	mech := []byte("SCRAM-SHA-256\x00\x00")
	switch f.mode {
	case "cleartext":
		_, _ = c.Write(auth(3, nil))
	case "md5":
		_, _ = c.Write(auth(5, []byte("salt")))
	case "gss":
		_, _ = c.Write(auth(7, nil))
	case "ok":
		_, _ = c.Write(append(auth(0, nil), readyForQuery...))
	case "ready":
		_, _ = c.Write(readyForQuery)
	case "sasl-other":
		_, _ = c.Write(auth(10, []byte("SCRAM-SHA-1\x00\x00")))
	case "sasl-then-ok":
		_, _ = c.Write(auth(10, mech))
		f.record(c, 1)
		_, _ = c.Write(append(auth(0, nil), readyForQuery...))
	case "sasl-then-cleartext":
		_, _ = c.Write(auth(10, mech))
		f.record(c, 1)
		_, _ = c.Write(auth(3, nil))
	case "truncated":
		_, _ = c.Write([]byte{'R', 0, 0, 0, 8, 0})
		return
	case "oversized":
		_, _ = c.Write([]byte{'R', 0x7f, 0, 0, 0})
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	f.record(c, -1)
}

// record reads n frontend messages (n < 0: until EOF/timeout).
func (f *fakePG) record(c net.Conn, n int) {
	for i := 0; n < 0 || i < n; i++ {
		h := make([]byte, 5)
		if _, err := io.ReadFull(c, h); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(h[1:])-4)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, append(h, body...)...)
		f.mu.Unlock()
	}
}

func (f *fakePG) passwordMessages() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for i := 0; i+5 <= len(f.received); {
		n := int(binary.BigEndian.Uint32(f.received[i+1:]))
		if f.received[i] == 'p' {
			out = append(out, f.received[i+5:i+1+n])
		}
		i += 1 + n
	}
	return out
}

func fixtureTLS(t *testing.T, dir string) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func guardedConnect(t *testing.T, dsn string, guard bool) error {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if guard {
		cfg.BuildFrontend = scramOnlyFrontend
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		conn.Close(ctx)
	}
	return err
}

func TestSCRAMOnlyRefusesBeforeAnyPasswordMessage(t *testing.T) {
	dir := t.TempDir()
	tlsConf := fixtureTLS(t, dir)
	for _, mode := range []string{"cleartext", "md5", "gss", "ok", "ready", "sasl-other", "sasl-then-ok", "sasl-then-cleartext", "truncated", "oversized"} {
		for _, useTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%t", mode, useTLS), func(t *testing.T) {
				var conf *tls.Config
				dsn := "postgres://fixture:%s@%s/postgres?sslmode=disable&connect_timeout=3"
				if useTLS {
					conf = tlsConf
					dsn = "postgres://fixture:%s@%s/postgres?sslmode=verify-full&sslrootcert=" + filepath.Join(dir, "ca.pem") + "&connect_timeout=3"
				}
				f := newFakePG(t, mode, conf)
				err := guardedConnect(t, fmt.Sprintf(dsn, fixturePassword, f.ln.Addr()), true)
				if err == nil {
					t.Fatal("connection accepted without SCRAM")
				}
				f.ln.Close()
				<-f.done
				if !f.startup {
					t.Fatal("fake server never reached the authentication phase")
				}
				for _, p := range f.passwordMessages() {
					// only a SASLInitialResponse naming SCRAM-SHA-256 may appear
					if !strings.HasPrefix(string(p), "SCRAM-SHA-256\x00") {
						t.Fatalf("credential-bearing message sent: %q", p)
					}
				}
				if strings.Contains(string(f.received), fixturePassword) || strings.Contains(err.Error(), fixturePassword) {
					t.Fatal("fixture password left the client")
				}
				if strings.HasPrefix(mode, "sasl-then") && len(f.passwordMessages()) != 1 {
					t.Fatalf("expected exactly the SASLInitialResponse, got %d", len(f.passwordMessages()))
				}
			})
		}
	}
}

// The recorder is not vacuous: without the guard pgx answers a cleartext
// request (over verified TLS) with the password.
func TestSCRAMOnlyRecorderControl(t *testing.T) {
	dir := t.TempDir()
	f := newFakePG(t, "cleartext", fixtureTLS(t, dir))
	_ = guardedConnect(t, fmt.Sprintf("postgres://fixture:%s@%s/postgres?sslmode=verify-full&sslrootcert=%s&connect_timeout=3",
		fixturePassword, f.ln.Addr(), filepath.Join(dir, "ca.pem")), false)
	f.ln.Close()
	<-f.done
	got := f.passwordMessages()
	if len(got) != 1 || string(got[0]) != fixturePassword+"\x00" {
		t.Fatalf("control did not observe the cleartext PasswordMessage: %q", got)
	}
}

func TestSCRAMOnlyOpenRefusesFallbacks(t *testing.T) {
	_, err := Open(context.Background(), Config{DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=prefer", RequireSCRAM: true})
	if err == nil || err.Error() != "pgstore: invalid DSN" {
		t.Fatalf("fallback DSN accepted: %v", err)
	}
}

// A real server that authenticates by trust (AuthenticationOk without SCRAM)
// is refused; set NTS_NEXUS_TEST_DSN to such a disposable loopback server.
func TestSCRAMOnlyRefusesRealTrustServer(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("set NTS_NEXUS_TEST_DSN to a disposable PostgreSQL database")
	}
	if err := guardedConnect(t, dsn, false); err != nil {
		t.Skip("control connection failed")
	}
	cfg, _ := pgconn.ParseConfig(dsn)
	cfg.BuildFrontend = scramOnlyFrontend
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		// the server negotiated SCRAM: acceptable, but then this is not a trust server
		conn.Close(ctx)
		t.Skip("NTS_NEXUS_TEST_DSN server uses SCRAM; trust refusal not observable")
	}
}

// Against a disposable SCRAM server (NTS_NEXUS_SCRAM_TEST_DSN, password in the
// DSN): Open with RequireSCRAM succeeds and the session works.
func TestSCRAMOnlyRealServerSucceeds(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_SCRAM_TEST_DSN")
	if dsn == "" {
		t.Skip("set NTS_NEXUS_SCRAM_TEST_DSN to a disposable PostgreSQL with scram-sha-256 host auth")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{DSN: dsn, RequireSCRAM: true, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var one int
	if err := s.Pool().QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal(err)
	}
}

func TestPasswordFieldNeedsPasswordlessDSN(t *testing.T) {
	_, err := Open(context.Background(), Config{DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable", Password: "public-fixture-password", RequireSCRAM: true})
	if err == nil || err.Error() != "pgstore: invalid DSN" {
		t.Fatalf("two password sources accepted: %v", err)
	}
}
