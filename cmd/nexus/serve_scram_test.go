//go:build linux || darwin

package main

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
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

// BBP-R1: B's normal serve wiring (run -> nexusserver.ConfigFromEnv ->
// storeConfig -> pgstore.Open) refuses a cleartext password request before any
// PasswordMessage, also over verified TLS, while production TLS validation is
// retained. The assertions are on what a recording fake server received.

const serveSentinel = "public-sentinel-serve-scram-0123"

type cleartextPG struct {
	ln      net.Listener
	tlsConf *tls.Config
	mu      sync.Mutex
	got     []byte
	conns   int
	wg      sync.WaitGroup
}

// newCleartextPG accepts connections on ln and asks each one for a cleartext
// password (AuthenticationCleartextPassword), recording every frontend byte.
func newCleartextPG(t *testing.T, ln net.Listener, tlsConf *tls.Config) *cleartextPG {
	f := &cleartextPG{ln: ln, tlsConf: tlsConf}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.handle(c) }()
		}
	}()
	t.Cleanup(func() { ln.Close(); f.wg.Wait() })
	return f
}

func (f *cleartextPG) handle(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = raw
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(head[:4])
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
		size = binary.BigEndian.Uint32(head[:4])
		if size < 4 || size > 1<<16 {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, size-4)); err != nil {
			return
		}
	} else if size < 8 || size > 1<<16 {
		return
	} else if _, err := io.ReadFull(c, make([]byte, size-8)); err != nil {
		return
	}
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()
	_, _ = c.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) // cleartext password request
	_ = c.SetDeadline(time.Now().Add(time.Second))
	for {
		h := make([]byte, 5)
		if _, err := io.ReadFull(c, h); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(h[1:])
		if n < 4 || n > 1<<16 {
			return
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		f.mu.Lock()
		f.got = append(f.got, append(h, body...)...)
		f.mu.Unlock()
		// Answer a PasswordMessage with a fixed auth failure so the client stops.
		_, _ = c.Write([]byte("E\x00\x00\x00\x24SFATAL\x00C28P01\x00Mfixture refusal\x00\x00"))
		return
	}
}

func (f *cleartextPG) result() (conns int, passwordMessages int, sawSentinel bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i+5 <= len(f.got); {
		n := int(binary.BigEndian.Uint32(f.got[i+1:]))
		if f.got[i] == 'p' {
			passwordMessages++
		}
		i += 1 + n
	}
	return f.conns, passwordMessages, strings.Contains(string(f.got), serveSentinel)
}

func serveFixtureTLS(t *testing.T, dir string) *tls.Config {
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

func clearServeEnv(t *testing.T) {
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "DATABASE_URL" || strings.HasPrefix(k, "NEXUS_") || strings.HasPrefix(k, "PG") || k == "PORT" {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
}

func listenLoopback(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// Production configuration (verify-full, no development flag) turns the guard
// on in the exact store config that serve opens, and that config refuses a
// cleartext request over verified TLS. The DSN is the production-validated one
// with only the port redirected to the fixture listener (ConfigFromEnv pins 5432).
func TestServeStoreConfigProductionRequiresSCRAM(t *testing.T) {
	dir := t.TempDir()
	tlsConf := serveFixtureTLS(t, dir)
	ca := filepath.Join(dir, "ca.pem")
	prodDSN := "postgres://newtype_runtime:" + serveSentinel + "@127.0.0.1:5432/newtype?sslmode=verify-full&sslrootcert=" + url.QueryEscape(ca) + "&connect_timeout=3"
	env := map[string]string{"DATABASE_URL": prodDSN, "NEXUS_DB_SCHEMA": "newtype_test", "NEXUS_DB_ROLE": "newtype_runtime"}
	cfg, err := nexusserver.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	sc := storeConfig(cfg)
	if !sc.RequireSCRAM {
		t.Fatal("production serve store config does not require SCRAM")
	}
	for _, guarded := range []bool{true, false} {
		ln := listenLoopback(t)
		fake := newCleartextPG(t, ln, tlsConf)
		c := sc
		c.DSN = strings.Replace(prodDSN, ":5432/", ":"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)+"/", 1)
		c.RequireSCRAM = guarded
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		store, err := pgstore.Open(ctx, c)
		cancel()
		if err == nil {
			store.Close()
			t.Fatal("fixture cleartext server accepted")
		}
		if strings.Contains(err.Error(), serveSentinel) {
			t.Fatal("error echoes the password")
		}
		ln.Close()
		fake.wg.Wait()
		conns, pw, saw := fake.result()
		if conns == 0 {
			t.Fatalf("guarded=%v: no verified-TLS startup reached the fixture", guarded)
		}
		if guarded && (pw != 0 || saw) {
			t.Fatalf("guarded serve config sent %d PasswordMessage(s)", pw)
		}
		if !guarded && (pw == 0 || !saw) {
			// Negative control: the recorder must be able to see a password.
			t.Fatal("recorder control saw no PasswordMessage without the guard")
		}
	}
}

// The full run() serve path honours the configuration: the local-development
// exception with NEXUS_DB_REQUIRE_SCRAM=1 refuses before any PasswordMessage;
// NEXUS_DB_REQUIRE_SCRAM=0 (development only) is the recorder control.
func TestServeRunRefusesCleartextBeforePassword(t *testing.T) {
	for _, tc := range []struct {
		setting string
		guarded bool
	}{{"1", true}, {"0", false}} {
		t.Run("NEXUS_DB_REQUIRE_SCRAM="+tc.setting, func(t *testing.T) {
			clearServeEnv(t)
			ln := listenLoopback(t)
			fake := newCleartextPG(t, ln, nil)
			t.Setenv("DATABASE_URL", "postgres://newtype_runtime:"+serveSentinel+"@"+ln.Addr().String()+"/newtype?sslmode=disable&connect_timeout=3")
			t.Setenv("NEXUS_DB_SCHEMA", "newtype_test")
			t.Setenv("NEXUS_ALLOW_LOCAL_DB", "1")
			t.Setenv("NEXUS_DB_REQUIRE_SCRAM", tc.setting)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := run(ctx, []string{"serve"}, strings.NewReader(""))
			if err == nil || !strings.HasPrefix(err.Error(), "nexus: database connection failed (") || strings.Contains(err.Error(), serveSentinel) {
				t.Fatalf("run: %v", err)
			}
			ln.Close()
			fake.wg.Wait()
			conns, pw, saw := fake.result()
			if conns == 0 {
				t.Fatal("no startup reached the fixture")
			}
			if tc.guarded && (pw != 0 || saw) {
				t.Fatalf("serve sent %d PasswordMessage(s) to a cleartext request", pw)
			}
			if !tc.guarded && (pw == 0 || !saw) {
				t.Fatal("recorder control saw no PasswordMessage")
			}
		})
	}
}

// The full run() path with a production configuration on the pinned port: the
// guard is on by default and a cleartext request over verified TLS gets no
// password. Needs 127.0.0.1:5432 free; skipped otherwise.
func TestServeRunProductionPortRefusesCleartext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:5432")
	if err != nil {
		t.Skip("127.0.0.1:5432 unavailable for the production-shape fixture")
	}
	clearServeEnv(t)
	dir := t.TempDir()
	fake := newCleartextPG(t, ln, serveFixtureTLS(t, dir))
	t.Setenv("DATABASE_URL", "postgres://newtype_runtime:"+serveSentinel+"@127.0.0.1:5432/newtype?sslmode=verify-full&sslrootcert="+url.QueryEscape(filepath.Join(dir, "ca.pem"))+"&connect_timeout=3")
	t.Setenv("NEXUS_DB_SCHEMA", "newtype_test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = run(ctx, []string{"serve"}, strings.NewReader(""))
	if err == nil || !strings.HasPrefix(err.Error(), "nexus: database connection failed (") {
		t.Fatalf("run: %v", err)
	}
	ln.Close()
	fake.wg.Wait()
	conns, pw, saw := fake.result()
	if conns == 0 || pw != 0 || saw {
		t.Fatalf("conns=%d passwordMessages=%d", conns, pw)
	}
	// Production may not opt out.
	t.Setenv("NEXUS_DB_REQUIRE_SCRAM", "0")
	if err := run(ctx, []string{"serve"}, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "NEXUS_DB_REQUIRE_SCRAM=0") {
		t.Fatalf("opt-out: %v", err)
	}
}

// The guarded serve wiring still works against a real SCRAM server: the full
// run() path migrates and passes the serve schema check with
// NEXUS_DB_REQUIRE_SCRAM=1 (disposable loopback cluster only).
func TestServeRunSCRAMRealServer(t *testing.T) {
	dsn := scramDSN(t)
	schema, role := schema6(t, dsn)
	clearServeEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("NEXUS_DB_SCHEMA", schema)
	t.Setenv("NEXUS_DB_ROLE", role)
	t.Setenv("NEXUS_ALLOW_LOCAL_DB", "1")
	t.Setenv("NEXUS_DB_REQUIRE_SCRAM", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := run(ctx, []string{"migrate"}, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if v := versions(t, dsn, schema); v != [3]int{9, 1, 4} {
		t.Fatalf("versions %v", v)
	}
}
