package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

const (
	dmOwner   = "owner@example.test"
	dmKeyEnv  = "env-key-0123456789abcdef"
	dmKeyNew  = "operator-key-fedcba9876543210ZZ"
	dmKeyNew2 = "second-operator-key-0000000000"
	dmHostA   = "res-a.services.ai.azure.com"
	dmHostB   = "res-b.services.ai.azure.com"
)

// dmRoute sends each Foundry host to its own httptest upstream, so the real
// endpoint validation runs while no network is used.
type dmRoute map[string]*httptest.Server

func (m dmRoute) RoundTrip(r *http.Request) (*http.Response, error) {
	srv, ok := m[r.URL.Host]
	if !ok {
		return nil, errors.New("unrouted host")
	}
	u, _ := url.Parse(srv.URL)
	clone := r.Clone(r.Context())
	clone.URL.Scheme, clone.URL.Host, clone.Host = u.Scheme, u.Host, r.URL.Host
	return srv.Client().Transport.RoundTrip(clone)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type dmFixture struct {
	t             *testing.T
	ctx           context.Context
	svc           *nexus.Service
	creds         *MemoryCredentials
	owner         nexus.Principal
	tokens        map[string][2]string // name -> licence, login
	root          nexus.Issued
	model         *ModelHandler
	op            *DefaultModelOperator
	sealer        *seal.Sealer
	storeDir      string
	storage       *FileDefaultModelStore
	approvals     *changeFixture
	admin         *httptest.Server
	audit         *Audit
	auditOut      *syncBuffer
	seen          map[string]*atomic.Value // host -> last Authorization
	routes        dmRoute
	release       chan struct{}
	started       chan struct{}
	slow          atomic.Bool
	mismatchedKey atomic.Int32
	bodies        []string
}

func newDMFixture(t *testing.T) *dmFixture {
	t.Helper()
	f := &dmFixture{t: t, ctx: context.Background(), creds: NewMemoryCredentials(), tokens: map[string][2]string{}, seen: map[string]*atomic.Value{}, routes: dmRoute{}, release: make(chan struct{}), started: make(chan struct{}, 4)}
	f.svc = nexus.NewService(nexus.NewMemStore(), nil)
	f.owner = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), dmOwner)
	var err error
	f.root, err = f.svc.CreateRoot(f.ctx, f.owner, nexus.RootRequest{Title: "model", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 10_000_000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.person("owner", f.owner.AccountID, dmOwner)
	f.person("manager", f.owner.AccountID, "manager@example.test")
	f.person("other", ids.Account(ids.New(ids.KindAccount)), "other@example.test")
	for host, key := range map[string]string{dmHostA: dmKeyEnv, dmHostB: dmKeyNew} {
		host, key := host, key
		last := &atomic.Value{}
		f.seen[host] = last
		f.routes[host] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			last.Store(auth)
			// Endpoint and key belong together: a torn snapshot would pair them wrongly.
			if auth != "Bearer "+key && !(host == dmHostB && auth == "Bearer "+dmKeyNew2) {
				f.mismatchedKey.Add(1)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"from-"+host[:5]+"\"}}]}\n\n")
			w.(http.Flusher).Flush()
			if f.slow.Load() && host == dmHostA {
				f.started <- struct{}{}
				<-f.release
			}
			_, _ = io.WriteString(w, "data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\ndata: [DONE]\n\n")
		}))
		t.Cleanup(f.routes[host].Close)
	}
	upstream, err := FoundryModelEndpoint("https://"+dmHostA, "chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	f.model, err = NewModelHandler(ModelConfig{Service: f.svc, Store: f.creds, Upstream: upstream, Key: dmKeyEnv, Models: []string{"fixture"}, Budget: 4000, MaxOutput: 100, Transport: f.routes})
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{7}, 32)
	deriver, _ := seal.NewMasterDeriver(master)
	signer, err := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), "kid-fixture")
	if err != nil {
		t.Fatal(err)
	}
	f.sealer = &seal.Sealer{Signer: signer, Deriver: deriver}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	f.storeDir = filepath.Join(dir, "operator")
	if err := os.Mkdir(f.storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.storage, err = NewFileDefaultModelStore(filepath.Join(f.storeDir, "default-model.sealed"))
	if err != nil {
		t.Fatal(err)
	}
	f.approvals = newChangeFixture(t)
	f.approvals.now = time.Now().UTC()
	f.admin = httptest.NewServer(f.approvals.h.AdminHandler())
	t.Cleanup(f.admin.Close)
	f.auditOut = &syncBuffer{}
	f.audit, _ = NewAudit(f.auditOut)
	t.Cleanup(func() { f.audit.Close() })
	f.op = f.newOperator(f.model, true)
	return f
}

func (f *dmFixture) person(name string, account ids.Account, email string) {
	lic, login := "ntl_"+strings.Repeat(string(rune('a'+len(f.tokens))), 64), "ntg_"+strings.Repeat(string(rune('a'+len(f.tokens))), 64)
	for token, kind := range map[string]string{lic: "licence", login: "login"} {
		if err := f.creds.PutCredential(f.ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: email, Expires: time.Now().Add(time.Hour)}); err != nil {
			f.t.Fatal(err)
		}
	}
	f.tokens[name] = [2]string{lic, login}
}

func (f *dmFixture) newOperator(model *ModelHandler, withApprovals bool) *DefaultModelOperator {
	f.t.Helper()
	cfg := DefaultModelConfig{Model: model, Service: f.svc, Store: f.creds, OwnerEmail: dmOwner, Sealer: f.sealer, Storage: f.storage, Audit: f.audit}
	if withApprovals {
		client, err := NewChangeAdminClient(f.admin.URL, f.approvals.admin, nil)
		if err != nil {
			f.t.Fatal(err)
		}
		cfg.Approvals = client
	}
	op, err := NewDefaultModelOperator(f.ctx, cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return op
}

// call sends an operator request; headers is applied after the owner's
// credentials so a test can strip or replace them.
func (f *dmFixture) call(who, method, path, body string, mutate func(*http.Request)) (int, string) {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if tok, ok := f.tokens[who]; ok {
		r.Header.Set("Authorization", "Bearer "+tok[0])
		r.Header.Set("X-Newtype-Login", tok[1])
	}
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	f.op.ServeHTTP(w, r)
	out := w.Body.String()
	f.bodies = append(f.bodies, out)
	return w.Code, out
}

// modelCall makes one metered session call through the user-facing proxy.
func (f *dmFixture) modelCall(h *ModelHandler) string {
	f.t.Helper()
	r := httptest.NewRequest("POST", "/v1/model/chat/completions", strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	tok := f.tokens["owner"]
	r.Header.Set("Authorization", "Bearer "+tok[0])
	r.Header.Set("X-Newtype-Login", tok[1])
	r.Header.Set("X-Newtype-Session", string(f.root.Session.ID))
	r.Header.Set("X-Newtype-Delegation", string(f.root.Delegation.ID))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		f.t.Fatalf("model call %d %s", w.Code, w.Body)
	}
	f.bodies = append(f.bodies, w.Body.String())
	return w.Body.String()
}

func (f *dmFixture) noSecretAnywhere() {
	f.t.Helper()
	f.audit.Close()
	all := strings.Join(f.bodies, "\n") + f.auditOut.String()
	raw, _ := os.ReadFile(f.approvals.path)
	all += string(raw) + f.approvals.mail.link
	for _, key := range []string{dmKeyEnv, dmKeyNew, dmKeyNew2, dmKeyNew[len(dmKeyNew)-4:]} {
		if strings.Contains(all, key) {
			f.t.Fatalf("key material leaked into a response, audit or approval record")
		}
	}
}

func changeBody(endpoint, protocol, key string) string {
	raw, _ := json.Marshal(map[string]string{"endpoint": endpoint, "protocol": protocol, "key": key})
	return string(raw)
}

func (f *dmFixture) decide(change DefaultModelChange, decision string) {
	f.t.Helper()
	u, err := url.Parse(f.approvals.mail.link)
	if err != nil || u.Query().Get("id") == "" {
		f.t.Fatal("no approval mail")
	}
	a, err := f.approvals.store.Get(u.Query().Get("id"), f.approvals.now)
	if err != nil || !strings.Contains(a.Manifest, change.ChangeID) {
		f.t.Fatal("approval does not name the change")
	}
	v := f.approvals.form(a)
	v.Set("decision", decision)
	if w := f.approvals.decide(v); w.Code != 200 {
		f.t.Fatalf("decide %d", w.Code)
	}
}

func TestDefaultModelSwapIsAtomicAndInFlightSafe(t *testing.T) {
	f := newDMFixture(t)
	if out := f.modelCall(f.model); !strings.Contains(out, "from-res-a") {
		t.Fatal("env upstream not used")
	}
	// A call in flight on A keeps A and its key even after the swap to B.
	f.slow.Store(true)
	done := make(chan string, 1)
	go func() { done <- f.modelCall(f.model) }()
	<-f.started
	upB, _ := FoundryModelEndpoint("https://"+dmHostB, "chat/completions")
	if err := f.model.SwapUpstream(upB, dmKeyNew, "operator", time.Now(), dmOwner); err != nil {
		t.Fatal(err)
	}
	if out := f.modelCall(f.model); !strings.Contains(out, "from-res-b") {
		t.Fatal("new calls must use the swapped upstream")
	}
	close(f.release)
	if out := <-done; !strings.Contains(out, "from-res-a") || !strings.Contains(out, "[DONE]") {
		t.Fatal("in-flight call did not finish on its snapshot")
	}
	f.slow.Store(false)
	// Concurrent swaps never pair one endpoint with the other's key.
	upA, _ := FoundryModelEndpoint("https://"+dmHostA, "chat/completions")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				_ = f.model.SwapUpstream(upA, dmKeyEnv, "operator", time.Now(), dmOwner)
			} else {
				_ = f.model.SwapUpstream(upB, dmKeyNew, "operator", time.Now(), dmOwner)
			}
		}
	}()
	for i := 0; i < 30; i++ {
		f.modelCall(f.model)
	}
	close(stop)
	wg.Wait()
	if f.mismatchedKey.Load() != 0 {
		t.Fatal("torn upstream/key snapshot")
	}
	// Invalid swaps leave the snapshot untouched.
	before := f.model.up.Load()
	for _, bad := range [][2]string{{"http://" + dmHostB + "/openai/v1/chat/completions", dmKeyNew}, {upB, "short"}, {upB, "has space in the key 0123"}, {"https://" + dmHostB + "/v1/other", dmKeyNew}} {
		if f.model.SwapUpstream(bad[0], bad[1], "operator", time.Now(), dmOwner) == nil {
			t.Fatal("invalid swap accepted")
		}
	}
	if f.model.up.Load() != before {
		t.Fatal("rejected swap changed the snapshot")
	}
	f.noSecretAnywhere()
}

func TestDefaultModelChangeNeedsOwnerAndEmailApproval(t *testing.T) {
	f := newDMFixture(t)
	code, out := f.call("owner", "GET", "/v1/operator/default-model", "", nil)
	var st DefaultModelStatus
	if code != 200 || json.Unmarshal([]byte(out), &st) != nil || st.Source != "env" || st.EndpointHost != dmHostA || st.Key != "set" || st.Protocol != "chat/completions" || !st.ChangeAvailable || len(st.Models) != 1 {
		t.Fatalf("status %d %s", code, out)
	}
	code, out = f.call("owner", "PUT", "/v1/operator/default-model", changeBody("https://"+dmHostB, "", dmKeyNew), nil)
	var ch DefaultModelChange
	if code != 202 || json.Unmarshal([]byte(out), &ch) != nil || ch.Status != "pending_approval" || ch.EndpointHost != dmHostB || f.approvals.mail.calls != 1 {
		t.Fatalf("begin %d %s", code, out)
	}
	// Nothing changes before the mailed approval, neither live nor stored.
	if _, err := f.storage.Load(f.ctx); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stored before approval")
	}
	f.op.ResolvePending(f.ctx)
	if code, _ = f.call("owner", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil); code != 202 {
		t.Fatalf("apply before approval %d", code)
	}
	if out := f.modelCall(f.model); !strings.Contains(out, "from-res-a") {
		t.Fatal("pending change took effect")
	}
	// Pending candidate is held sealed only.
	f.op.mu.Lock()
	if p := f.op.pending[ch.ChangeID]; bytes.Contains(p.sealed, []byte(dmKeyNew)) || len(p.sealed) == 0 {
		t.Fatal("pending key not sealed")
	}
	f.op.mu.Unlock()
	f.decide(ch, "approve")
	// A non-owner cannot apply even an approved change.
	if code, _ = f.call("manager", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil); code != 403 {
		t.Fatalf("manager apply %d", code)
	}
	code, out = f.call("owner", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil)
	if code != 200 || json.Unmarshal([]byte(out), &ch) != nil || ch.Status != "applied" || ch.Current == nil || ch.Current.Source != "operator" || ch.Current.UpdatedBy != dmOwner || ch.Current.UpdatedAt.IsZero() {
		t.Fatalf("apply %d %s", code, out)
	}
	if out := f.modelCall(f.model); !strings.Contains(out, "from-res-b") {
		t.Fatal("approved change not live")
	}
	if a, _ := f.approvals.store.Get(mustQuery(t, f.approvals.mail.link, "id"), f.approvals.now); a.Status != "consumed" || a.Result != "succeeded" {
		t.Fatalf("approval not consumed/reported: %s %s", a.Status, a.Result)
	}
	// Replaying the apply is not a second change.
	if code, _ = f.call("owner", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil); code != 404 {
		t.Fatalf("replay %d", code)
	}

	// Denied: the current upstream stays.
	code, out = f.call("owner", "PUT", "/v1/operator/default-model", changeBody("https://"+dmHostA, "chat/completions", dmKeyNew2), nil)
	if code != 202 || json.Unmarshal([]byte(out), &ch) != nil {
		t.Fatalf("second begin %d", code)
	}
	f.decide(ch, "deny")
	if code, out = f.call("owner", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil); code != 409 || !strings.Contains(out, "approval_denied") {
		t.Fatalf("denied apply %d %s", code, out)
	}
	if out := f.modelCall(f.model); !strings.Contains(out, "from-res-b") {
		t.Fatal("denied change altered the upstream")
	}

	// Expired: the current upstream stays.
	code, out = f.call("owner", "PUT", "/v1/operator/default-model", changeBody("https://"+dmHostA, "", dmKeyNew2), nil)
	if code != 202 || json.Unmarshal([]byte(out), &ch) != nil {
		t.Fatalf("third begin %d", code)
	}
	f.op.cfg.Clock = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if code, out = f.call("owner", "POST", "/v1/operator/default-model/changes/"+ch.ChangeID+"/apply", "", nil); code != 409 || !strings.Contains(out, "approval_expired") {
		t.Fatalf("expired apply %d %s", code, out)
	}
	f.op.cfg.Clock = time.Now
	if f.op.Status().EndpointHost != dmHostB {
		t.Fatal("expired change altered the upstream")
	}

	// Background resolution applies an approved change without an apply call.
	code, out = f.call("owner", "PUT", "/v1/operator/default-model", changeBody("https://"+dmHostB, "", dmKeyNew2), nil)
	if code != 202 || json.Unmarshal([]byte(out), &ch) != nil {
		t.Fatalf("fourth begin %d", code)
	}
	f.decide(ch, "approve")
	f.op.ResolvePending(f.ctx)
	if !strings.Contains(f.modelCall(f.model), "from-res-b") || f.seen[dmHostB].Load() != "Bearer "+dmKeyNew2 {
		t.Fatal("background apply did not swap the key")
	}
	f.noSecretAnywhere()
	if !strings.Contains(f.auditOut.String(), "default_model.applied") || !strings.Contains(f.auditOut.String(), "default_model.change_requested") {
		t.Fatal("audit events missing")
	}
}

func mustQuery(t *testing.T, link, key string) string {
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestDefaultModelStoredValueTakesPrecedenceAndIsSealed(t *testing.T) {
	f := newDMFixture(t)
	upB, _ := FoundryModelEndpoint("https://"+dmHostB, "responses")
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	sealed, err := sealDefaultModel(f.ctx, f.sealer, defaultModelRecord{Upstream: upB, Key: dmKeyNew, UpdatedAt: at, UpdatedBy: dmOwner, ChangeID: "dmc_fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(dmKeyNew)) || bytes.Contains(sealed, []byte(dmHostB)) {
		t.Fatal("plaintext in sealed envelope")
	}
	if err := f.storage.Save(f.ctx, sealed); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(f.storeDir, "default-model.sealed"))
	if bytes.Contains(raw, []byte(dmKeyNew)) {
		t.Fatal("key on disk")
	}
	if info, _ := os.Stat(filepath.Join(f.storeDir, "default-model.sealed")); info.Mode().Perm() != 0o600 {
		t.Fatal("store mode")
	}
	// Stored operator value wins over the env bootstrap at startup.
	upA, _ := FoundryModelEndpoint("https://"+dmHostA, "chat/completions")
	fresh, err := NewModelHandler(ModelConfig{Service: f.svc, Store: f.creds, Upstream: upA, Key: dmKeyEnv, Models: []string{"fixture"}, Budget: 4000, MaxOutput: 100, Transport: f.routes})
	if err != nil {
		t.Fatal(err)
	}
	op := f.newOperator(fresh, false)
	st := op.Status()
	if st.Source != "operator" || st.EndpointHost != dmHostB || st.Protocol != "responses" || !st.UpdatedAt.Equal(at) || st.UpdatedBy != dmOwner || st.ChangeAvailable {
		t.Fatalf("precedence %+v", st)
	}
	if fresh.Protocol() != "responses" {
		t.Fatal("protocol route not following stored value")
	}
	// Without a stored value the env value is used.
	if err := os.Remove(filepath.Join(f.storeDir, "default-model.sealed")); err != nil {
		t.Fatal(err)
	}
	fresh2, _ := NewModelHandler(ModelConfig{Service: f.svc, Store: f.creds, Upstream: upA, Key: dmKeyEnv, Models: []string{"fixture"}, Budget: 4000, MaxOutput: 100, Transport: f.routes})
	if st := f.newOperator(fresh2, false).Status(); st.Source != "env" || st.EndpointHost != dmHostA || !st.UpdatedAt.IsZero() {
		t.Fatalf("env %+v", st)
	}
	// A different sealing master cannot open it, and tampering is refused:
	// startup fails closed instead of silently returning to env.
	if err := f.storage.Save(f.ctx, sealed); err != nil {
		t.Fatal(err)
	}
	other, _ := seal.NewMasterDeriver(bytes.Repeat([]byte{8}, 32))
	if _, err := openDefaultModel(f.ctx, &seal.Sealer{Signer: f.sealer.Signer, Deriver: other}, sealed); err == nil {
		t.Fatal("opened with another master")
	}
	tampered := bytes.Replace(sealed, []byte(`"sealed":"e`), []byte(`"sealed":"f`), 1)
	if err := f.storage.Save(f.ctx, tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDefaultModelOperator(f.ctx, DefaultModelConfig{Model: fresh2, Service: f.svc, Store: f.creds, OwnerEmail: dmOwner, Sealer: f.sealer, Storage: f.storage}); err == nil {
		t.Fatal("tampered store accepted")
	}
	if _, err := NewDefaultModelOperator(f.ctx, DefaultModelConfig{Model: fresh2, Service: f.svc, Store: f.creds, OwnerEmail: dmOwner, Storage: f.storage}); err == nil {
		t.Fatal("storage without sealing accepted")
	}
	// An unsafe store file is refused rather than read or overwritten.
	if err := os.Chmod(filepath.Join(f.storeDir, "default-model.sealed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.storage.Load(f.ctx); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe store read")
	}
	if f.storage.Save(f.ctx, sealed) == nil {
		t.Fatal("unsafe store overwritten")
	}
}

func TestDefaultModelRefusesEveryoneButTheOwnerPerson(t *testing.T) {
	f := newDMFixture(t)
	nta := "nta_" + strings.Repeat("c", 64)
	if err := f.creds.PutCredential(f.ctx, Credential{Verifier: Verifier(nta), Kind: "agent", Account: f.owner.AccountID, Session: f.root.Session.ID, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	body := changeBody("https://"+dmHostB, "", dmKeyNew)
	cases := []struct {
		name, who string
		mutate    func(*http.Request)
		want      int
	}{
		{"session principal (TUI model root)", "owner", func(r *http.Request) { r.Header.Set("X-Newtype-Session", string(f.root.Session.ID)) }, 403},
		{"bot/agent credential", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+nta) }, 401},
		{"executor credential", "", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+nexus.ExecutorTokenPrefix+strings.Repeat("d", 64))
		}, 401},
		{"non-owner person in the owner's account (manager)", "manager", nil, 403},
		{"non-owner person elsewhere", "other", nil, 403},
		{"missing login", "owner", func(r *http.Request) { r.Header.Del("X-Newtype-Login") }, 401},
		{"login without licence", "owner", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"owner login with manager licence", "manager", func(r *http.Request) { r.Header.Set("X-Newtype-Login", f.tokens["owner"][1]) }, 403},
		{"owner licence with manager login", "owner", func(r *http.Request) { r.Header.Set("X-Newtype-Login", f.tokens["manager"][1]) }, 403},
	}
	for _, tc := range cases {
		for _, req := range [][3]string{{"GET", "/v1/operator/default-model", ""}, {"PUT", "/v1/operator/default-model", body}, {"POST", "/v1/operator/default-model", body}} {
			if code, out := f.call(tc.who, req[0], req[1], req[2], tc.mutate); code != tc.want || strings.Contains(out, dmHostA) {
				t.Fatalf("%s %s: %d %s", tc.name, req[0], code, out)
			}
		}
	}
	if f.approvals.mail.calls != 0 {
		t.Fatal("refused request reached approval mail")
	}
	// The user-facing model proxy is unchanged: the owner's session still works.
	if !strings.Contains(f.modelCall(f.model), "from-res-a") {
		t.Fatal("model proxy changed")
	}
	f.noSecretAnywhere()
}

func TestDefaultModelChangeValidation(t *testing.T) {
	f := newDMFixture(t)
	for _, body := range []string{
		changeBody("http://"+dmHostB, "", dmKeyNew),
		changeBody("https://"+dmHostB+":8443", "", dmKeyNew),
		changeBody("https://evil.example.com", "", dmKeyNew),
		changeBody("https://"+dmHostB+"/openai?x=1", "", dmKeyNew),
		changeBody("https://"+dmHostB, "agents", dmKeyNew),
		changeBody("https://"+dmHostB, "", "short"),
		changeBody("https://"+dmHostB, "", "key with spaces 0123456789"),
		changeBody("https://"+dmHostB, "", dmKeyNew+"\n"),
		`{"endpoint":"https://` + dmHostB + `","key":"` + dmKeyNew + `","models":["x"]}`,
		`{"endpoint":"https://` + dmHostB + `","key":"` + dmKeyNew + `"} {}`,
		`not json`,
	} {
		if code, out := f.call("owner", "PUT", "/v1/operator/default-model", body, nil); code != 400 {
			t.Fatalf("accepted %q: %d %s", body, code, out)
		}
	}
	if f.approvals.mail.calls != 0 || len(f.op.pending) != 0 {
		t.Fatal("invalid request started an approval")
	}
	// No approvals facility: status works, changes are refused (no bypass).
	f.op = f.newOperator(f.model, false)
	if code, _ := f.call("owner", "GET", "/v1/operator/default-model", "", nil); code != 200 {
		t.Fatal("status without approvals")
	}
	if code, out := f.call("owner", "PUT", "/v1/operator/default-model", changeBody("https://"+dmHostB, "", dmKeyNew), nil); code != 503 || !strings.Contains(out, "operator_change_unavailable") {
		t.Fatalf("change without approvals %d %s", code, out)
	}
	if f.op.Status().EndpointHost != dmHostA {
		t.Fatal("changed without approval")
	}
	f.noSecretAnywhere()
}

func TestModelProtocolRouteFollowsSnapshot(t *testing.T) {
	f := newDMFixture(t)
	w := httptest.NewRecorder()
	f.model.ProtocolRoute("responses").ServeHTTP(w, httptest.NewRequest("POST", "/v1/model/responses", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatalf("inactive protocol served: %d", w.Code)
	}
	upB, _ := FoundryModelEndpoint("https://"+dmHostB, "responses")
	if err := f.model.SwapUpstream(upB, dmKeyNew, "operator", time.Now(), dmOwner); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	f.model.ProtocolRoute("chat/completions").ServeHTTP(w, httptest.NewRequest("POST", "/v1/model/chat/completions", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatalf("old protocol still served: %d", w.Code)
	}
}
