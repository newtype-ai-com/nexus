package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
	"os"
)

func TestDevicePostgresHTTP(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := strings.Repeat("k", 40)
	lic := Credential{Verifier: Verifier(key), Kind: "licence", Account: ids.Account(ids.New(ids.KindAccount)), Email: "user@example.test", Expires: now.Add(time.Hour)}
	if st.PutCredential(ctx, lic) != nil {
		t.Fatal("licence")
	}
	mail := &fixtureMailer{}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{"example.test"}, Mailer: mail, Clock: func() time.Time { return now }}
	h, err := NewDeviceHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	call := func(method, path, token, body string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if strings.HasPrefix(body, "decision=") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal("request failed")
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("status %d want %d", res.StatusCode, want)
		}
		var raw json.RawMessage
		if strings.Contains(res.Header.Get("Content-Type"), "application/json") {
			if json.NewDecoder(res.Body).Decode(&raw) != nil {
				t.Fatal("decode")
			}
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
		return raw
	}
	call("POST", "/v1/device", "", "{}", 401)
	call("POST", "/v1/device", key, `{"account_id":"forged"}`, 400)
	raw := call("POST", "/v1/device", key, "{}", 200)
	var d DeviceStart
	if json.Unmarshal(raw, &d) != nil || d.Code == "" || strings.Contains(string(raw), "apv_") {
		t.Fatal("device start")
	}
	u, _ := url.Parse(mail.link)
	call("GET", u.RequestURI(), "", "", 200)
	body, _ := json.Marshal(map[string]string{"device_code": d.Code})
	raw = call("POST", "/v1/device/token", "", string(body), 400)
	if !strings.Contains(string(raw), "authorization_pending") {
		t.Fatal("GET approved request")
	}
	raw = call("POST", "/v1/device/token", "", string(body), 400)
	if !strings.Contains(string(raw), "slow_down") {
		t.Fatal("poll limiter")
	}
	// Restart pool and handler before approving and claiming.
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	cfg.Store = NewPostgresCredentials(second.Pool())
	h2, err := NewDeviceHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	server = httptest.NewServer(h2)
	defer server.Close()
	call("POST", u.RequestURI(), "", "decision=approve", 200)
	now = now.Add(11 * time.Second)
	raw = call("POST", "/v1/device/token", "", string(body), 200)
	var login struct {
		Token string `json:"session_token"`
	}
	if json.Unmarshal(raw, &login) != nil || login.Token == "" {
		t.Fatal("login response")
	}
	c, err := st.LookupCredential(ctx, Verifier(login.Token))
	if err != nil || c.Account != lic.Account || c.Kind != "login" {
		t.Fatal("wrong identity")
	}
	raw = call("POST", "/v1/device/token", "", string(body), 400)
	if !strings.Contains(string(raw), "expired_token") {
		t.Fatal("replayed claim")
	}
	var persisted string
	if db.Pool().QueryRow(ctx, `SELECT row_to_json(d)::text FROM gate_devices d WHERE device_hash=$1`, Verifier(d.Code)).Scan(&persisted) != nil {
		t.Fatal("stored device")
	}
	for _, secret := range []string{key, d.Code, u.Query().Get("t"), login.Token} {
		if strings.Contains(persisted, secret) {
			t.Fatal("plaintext persisted")
		}
	}
}

func TestDeviceConcurrentClaimRevocationAndExpiry(t *testing.T) {
	st, _, _ := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := strings.Repeat("q", 40)
	lic := Credential{Verifier: Verifier(key), Kind: "licence", Account: ids.Account(ids.New(ids.KindAccount)), Email: "one@example.test", Expires: now.Add(time.Hour)}
	if st.PutCredential(ctx, lic) != nil {
		t.Fatal("provision")
	}
	d, link, _, err := st.BeginDevice(ctx, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConfirmDevice(ctx, link, false, now) != nil {
		t.Fatal("approve")
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := st.ClaimDevice(ctx, d.Code, now)
			if err == nil {
				ok.Add(1)
			} else if !errors.Is(err, ErrDeviceExpired) {
				t.Error("unexpected claim error")
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatal("not single use")
	}
	d, link, _, err = st.BeginDevice(ctx, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConfirmDevice(ctx, link, true, now) != nil {
		t.Fatal("deny")
	}
	if _, _, err = st.ClaimDevice(ctx, d.Code, now); !errors.Is(err, ErrDeviceDenied) {
		t.Fatal("denial ignored")
	}
	d, link, _, err = st.BeginDevice(ctx, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConfirmDevice(ctx, link, false, now) != nil {
		t.Fatal("approve")
	}
	if st.RevokeCredential(ctx, lic.Verifier) != nil {
		t.Fatal("revoke")
	}
	if _, _, err = st.ClaimDevice(ctx, d.Code, now); !errors.Is(err, ErrDeviceDenied) {
		t.Fatal("revoked key issued login")
	}
	if _, _, err = st.ClaimDevice(ctx, d.Code, now.Add(10*time.Minute)); !errors.Is(err, ErrDeviceExpired) {
		t.Fatal("expiry")
	}
}
