package gate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ChangeMailer interface {
	SendChangeApproval(context.Context, string, string, string) error
}
type ChangeConfig struct {
	Store      ChangeStore
	Mailer     ChangeMailer
	BaseURL    string
	OwnerEmail string
	AdminToken string
	Clock      func() time.Time
	Audit      *Audit
}
type ChangeHandler struct {
	cfg           ChangeConfig
	public, admin *http.ServeMux
}

func NewChangeHandler(cfg ChangeConfig) (*ChangeHandler, error) {
	u, e := url.Parse(cfg.BaseURL)
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if cfg.Store == nil || cfg.Mailer == nil || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !ValidOwnerEmail(cfg.OwnerEmail) || len(cfg.AdminToken) < 32 || strings.ContainsAny(cfg.AdminToken, "\r\n\x00") {
		return nil, ErrChangeInvalid
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	h := &ChangeHandler{cfg: cfg, public: http.NewServeMux(), admin: http.NewServeMux()}
	h.public.HandleFunc("GET /change/approve", h.decide)
	h.public.HandleFunc("POST /change/approve", h.decide)
	h.public.HandleFunc("GET /change/decision.js", h.script)
	h.admin.HandleFunc("POST /v1/changes", h.begin)
	h.admin.HandleFunc("GET /v1/changes/{id}", h.poll)
	h.admin.HandleFunc("POST /v1/changes/{id}/consume", h.consume)
	h.admin.HandleFunc("POST /v1/changes/{id}/result", h.result)
	return h, nil
}
func (h *ChangeHandler) PublicHandler() http.Handler { return h.surface(h.public, false) }
func (h *ChangeHandler) AdminHandler() http.Handler  { return h.surface(h.admin, true) }
func (h *ChangeHandler) surface(next http.Handler, admin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", changeSurfaceCSP)
		if admin && (len(bearer(r)) != len(h.cfg.AdminToken) || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(h.cfg.AdminToken)) != 1) {
			gateError(w, 401, "unauthenticated")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func changeHTTPError(w http.ResponseWriter, e error) {
	code, msg := 503, "unavailable"
	switch {
	case errors.Is(e, ErrChangeInvalid):
		code, msg = 400, "invalid_request"
	case errors.Is(e, ErrChangeNotFound):
		code, msg = 404, "not_found"
	case errors.Is(e, ErrChangeConflict):
		code, msg = 409, "stale_or_conflict"
	case errors.Is(e, ErrChangeLimit):
		code, msg = 429, "mail_limit"
	}
	gateError(w, code, msg)
}
func decodeChange(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 120<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrChangeInvalid
	}
	return nil
}

// Operators must submit secret-free manifests. Reject configured credentials and
// common DSN/key material instead of attempting to redact a bound manifest.
func (h *ChangeHandler) safeInput(in ChangeInput) bool {
	raw, _ := json.Marshal(in)
	s := string(raw)
	for _, v := range []string{h.cfg.AdminToken, "postgres://", "postgresql://", "secret://", "PRIVATE KEY", "Bearer ", "cap_"} {
		if strings.Contains(s, v) {
			return false
		}
	}
	return true
}
func (h *ChangeHandler) event(kind string, a ChangeApproval) {
	if h.cfg.Audit != nil {
		h.cfg.Audit.Write(AuditEvent{Type: kind, RequestID: a.ID, Established: AuditEstablished{Outcome: a.Status}})
	}
}
func (h *ChangeHandler) begin(w http.ResponseWriter, r *http.Request) {
	var in ChangeInput
	if decodeChange(w, r, &in) != nil || !h.safeInput(in) {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	a, token, e := h.cfg.Store.Begin(in, h.cfg.Clock())
	if e != nil {
		changeHTTPError(w, e)
		return
	}
	if token != "" {
		summary := fmt.Sprintf("ID: %s\n종류: %s\n대상: %s\ndigest: %s\n기준 상태: %s\n영향: %s\n비용: %s\n복구: %s\n만료: %s", a.ID, a.Kind, a.Target, a.Digest, a.BaseState, a.Impact, a.Cost, a.Recovery, a.ExpiresAt.Format(time.RFC3339))
		link := h.cfg.BaseURL + "/change/approve?" + url.Values{"id": {a.ID}, "t": {token}}.Encode()
		e = h.cfg.Mailer.SendChangeApproval(r.Context(), h.cfg.OwnerEmail, summary, link)
		if de := h.cfg.Store.Delivery(a.ID, e == nil); de != nil {
			changeHTTPError(w, de)
			return
		}
		if e != nil {
			gateError(w, 502, "mail_unavailable")
			return
		}
		h.event("change.requested", a)
	}
	gateJSON(w, 202, a)
}
func (h *ChangeHandler) poll(w http.ResponseWriter, r *http.Request) {
	a, e := h.cfg.Store.Get(r.PathValue("id"), h.cfg.Clock())
	if e != nil {
		changeHTTPError(w, e)
		return
	}
	gateJSON(w, 200, a)
}
func (h *ChangeHandler) consume(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Manifest string `json:"manifest"`
	}
	if decodeChange(w, r, &in) != nil {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	a, e := h.cfg.Store.Consume(r.PathValue("id"), in.Manifest, h.cfg.Clock())
	if e != nil {
		changeHTTPError(w, e)
		return
	}
	h.event("change.consumed", a)
	gateJSON(w, 200, a)
}
func (h *ChangeHandler) result(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Result string `json:"result"`
	}
	if decodeChange(w, r, &in) != nil {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	a, e := h.cfg.Store.Result(r.PathValue("id"), in.Result, h.cfg.Clock())
	if e != nil {
		changeHTTPError(w, e)
		return
	}
	h.event("change.result", a)
	gateJSON(w, 200, a)
}

var changePage = approvalPage("change", "운영 변경 승인", `<span class="badge">운영 변경 승인</span><h1>운영 변경 승인</h1><p class="lead">열어 보는 것만으로는 승인되지 않습니다.</p><dl><div><dt>ID</dt><dd><code>{{.ID}}</code></dd></div><div><dt>상태</dt><dd>{{.Status}}</dd></div><div><dt>요청자</dt><dd>{{.Requester}}</dd></div><div><dt>종류</dt><dd>{{.Kind}}</dd></div><div><dt>대상</dt><dd>{{.Target}}</dd></div><div><dt>digest</dt><dd><code>{{.Digest}}</code></dd></div></dl><pre>{{.Manifest}}</pre><dl><div><dt>기준 상태</dt><dd>{{.BaseState}}</dd></div><div><dt>영향</dt><dd>{{.Impact}}</dd></div><div><dt>비용</dt><dd>{{.Cost}}</dd></div><div><dt>복구</dt><dd>{{.Recovery}}</dd></div><div><dt>만료</dt><dd>{{.ExpiresAt}}</dd></div><div><dt>결정 시각</dt><dd>{{.DecidedAt}}</dd></div></dl>{{if eq .Status "pending"}}<form id="decision" method="post" action="/change/approve"><input type="hidden" name="digest" value="{{.Digest}}"><button class="approve" disabled name="decision" value="approve">이 정확한 변경 승인</button><button class="deny" disabled name="decision" value="deny">거절</button></form><noscript>JavaScript 없이는 결정할 수 없습니다.</noscript><script src="/change/decision.js" defer></script>{{end}}`+approvalSecurityNote)

const changeScript = `"use strict";
const form = document.getElementById("decision");
const query = new URLSearchParams(location.search);
const id = query.get("id"), token = query.get("t");
if (form && id && token) {
 let submitted = false;
 for (const button of form.querySelectorAll("button")) button.disabled = false;
 form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!event.submitter || submitted) return;
  submitted = true;
  for (const button of form.querySelectorAll("button")) button.disabled = true;
  const body = new URLSearchParams({id, t: token, digest: form.elements.digest.value, decision: event.submitter.value});
  try {
   const response = await fetch("/change/approve", {method:"POST", body, credentials:"omit", cache:"no-store", referrerPolicy:"no-referrer"});
   form.textContent = response.ok ? "결정이 기록되었습니다. 다시 열면 상태를 확인할 수 있습니다." : "결정되지 않았습니다. 원래 링크에서 상태를 확인하세요.";
  } catch (_) { form.textContent = "결과를 확인할 수 없습니다. 원래 링크에서 상태를 확인하세요."; }
 });
}
`

func (h *ChangeHandler) script(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	if r.Method != "HEAD" {
		_, _ = io.WriteString(w, changeScript)
	}
}
func safeChangeIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}
func (h *ChangeHandler) decide(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" || r.Method == "HEAD" {
		q := r.URL.Query()
		if len(q["id"]) != 1 || len(q["t"]) != 1 {
			changeHTTPError(w, ErrChangeNotFound)
			return
		}
		a, e := h.cfg.Store.ByLink(q.Get("id"), q.Get("t"), h.cfg.Clock())
		if e != nil {
			changeHTTPError(w, e)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method != "HEAD" {
			_ = changePage.Execute(w, a)
		}
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.cfg.BaseURL {
		gateError(w, 403, "forbidden")
		return
	}
	if r.URL.RawQuery != "" {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.ParseForm() != nil {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	for _, key := range []string{"id", "t", "digest", "decision"} {
		if len(r.PostForm[key]) != 1 {
			changeHTTPError(w, ErrChangeInvalid)
			return
		}
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		changeHTTPError(w, ErrChangeInvalid)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ua := r.UserAgent()
	if len(ua) > 1024 {
		ua = ua[:1024]
	}
	// Store a fingerprint, never caller-controlled UA text (which can contain any token).
	a, e := h.cfg.Store.Decide(r.PostForm.Get("id"), r.PostForm.Get("t"), r.PostForm.Get("digest"), decision == "approve", ip, ua, h.cfg.Clock())
	if e != nil {
		changeHTTPError(w, e)
		return
	}
	h.event("change.decided", a)
	gateJSON(w, 200, a)
}
