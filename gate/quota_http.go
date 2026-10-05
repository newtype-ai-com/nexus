package gate

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type QuotaMailer interface {
	SendQuotaApproval(context.Context, string, string, string) error
}
type QuotaConfig struct {
	Service      *nexus.Service
	Store        CredentialStore
	Authenticate func(*http.Request) (nexus.Principal, error)
	Mailer       QuotaMailer
	BaseURL      string
	Clock        func() time.Time
	OwnerOnly    bool
	// OwnerEmail is the configured owner (NEXUS_OWNER_EMAIL): the only
	// address that receives approval mail and may act on other accounts.
	OwnerEmail string
}
type QuotaHandler struct {
	cfg QuotaConfig
	mux *http.ServeMux
}

func NewQuotaHandler(cfg QuotaConfig) (*QuotaHandler, error) {
	u, err := url.Parse(cfg.BaseURL)
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if !ValidOwnerEmail(cfg.OwnerEmail) || cfg.Service == nil || cfg.Store == nil || cfg.Authenticate == nil || cfg.Mailer == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, nexus.ErrInvalid
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	h := &QuotaHandler{cfg: cfg, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /v1/quota", h.status)
	h.mux.HandleFunc("POST /v1/quota/requests", h.start)
	h.mux.HandleFunc("GET /v1/quota/requests/{id}", h.poll)
	h.mux.HandleFunc("GET /quota/approve", h.decide)
	h.mux.HandleFunc("POST /quota/approve", h.decide)
	return h, nil
}
func (h *QuotaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second))
	w.Header().Set("Cache-Control", "no-store")
	// same-origin (decision 2026-10-04): with no-referrer a browser form POST carries
	// "Origin: null", which the Origin check refuses. The token URL still never
	// leaves this origin.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r.WithContext(ctx))
}
func (h *QuotaHandler) actor(w http.ResponseWriter, r *http.Request) (nexus.Principal, bool) {
	p, err := h.cfg.Authenticate(r)
	if err != nil {
		gateError(w, 401, "unauthenticated")
		return p, false
	}
	if p.Kind != nexus.PrincipalUser && p.Kind != nexus.PrincipalSession {
		gateError(w, 403, "forbidden")
		return p, false
	}
	return p, true
}
func (h *QuotaHandler) target(w http.ResponseWriter, r *http.Request, p nexus.Principal, target ids.Account) (nexus.Principal, bool) {
	if target == "" || target == p.AccountID {
		return p, true
	}
	if h.cfg.OwnerOnly {
		gateError(w, 403, "forbidden")
		return p, false
	}
	c, err := h.cfg.Store.LookupCredential(r.Context(), Verifier(bearer(r)))
	if err != nil || c.Kind != "licence" || c.Revoked || !h.cfg.Clock().Before(c.Expires) || !ValidOwnerEmail(h.cfg.OwnerEmail) || c.Email != h.cfg.OwnerEmail || c.Account != p.AccountID || ids.Check(ids.KindAccount, string(target)) != nil {
		gateError(w, 403, "forbidden")
		return p, false
	}
	return nexus.SystemPrincipal(target), true
}
func (h *QuotaHandler) status(w http.ResponseWriter, r *http.Request) {
	p, ok := h.actor(w, r)
	if !ok {
		return
	}
	p, ok = h.target(w, r, p, ids.Account(r.URL.Query().Get("account_id")))
	if !ok {
		return
	}
	q, err := h.cfg.Service.AccountQuota(r.Context(), p)
	if err != nil {
		gateError(w, 503, "unavailable")
		return
	}
	gateJSON(w, 200, q)
}
func publicQuotaRequest(a nexus.QuotaRequest) nexus.QuotaRequest { a.ApprovalHash = ""; return a }
func quotaRequestMonth(id string) (string, bool) {
	if len(id) != 76 || id[7:12] != "_qtr_" {
		return "", false
	}
	_, err := time.Parse("2006-01", id[:7])
	return id[:7], err == nil
}
func (h *QuotaHandler) start(w http.ResponseWriter, r *http.Request) {
	p, ok := h.actor(w, r)
	if !ok {
		return
	}
	var req struct {
		Amount  int64       `json:"amount"`
		Client  string      `json:"client_event_id"`
		Account ids.Account `json:"account_id,omitempty"`
	}
	if gateDecode(w, r, &req) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	requester := p.AccountID
	p, ok = h.target(w, r, p, req.Account)
	if !ok {
		return
	}
	token, err := randomToken("qap_")
	if err != nil {
		gateError(w, 503, "unavailable")
		return
	}
	id, err := randomToken("qtr_")
	if err != nil {
		gateError(w, 503, "unavailable")
		return
	}
	month, _ := nexus.QuotaMonth(h.cfg.Clock())
	id = month + "_" + id
	// Namespace idempotency by the authenticated requester, not just target.
	if len(req.Client) < 1 || len(req.Client) > 80 {
		gateError(w, 400, "invalid_request")
		return
	}
	a, fresh, err := h.cfg.Service.BeginQuotaRequest(r.Context(), p, id, string(requester)+":"+req.Client, Verifier(token), req.Amount)
	if err != nil {
		switch err {
		case nexus.ErrInvalid:
			gateError(w, 400, "invalid_request")
		case nexus.ErrLimit:
			gateError(w, 429, "rate_limited")
		default:
			gateError(w, 409, "request_conflict")
		}
		return
	}
	if fresh {
		values := url.Values{"account_id": {string(a.AccountID)}, "id": {a.ID}, "t": {token}}
		summary := fmt.Sprintf("계정 %s / %s (한국시간) / 기존 %d → 최종 %d 토큰 / 증액 %d 토큰. 당월에만 적용하며 다음 달 이월되지 않습니다.", a.AccountID, a.Month, a.PreviousLimit, a.NewLimit, a.Amount)
		if h.cfg.Mailer.SendQuotaApproval(r.Context(), h.cfg.OwnerEmail, summary, h.cfg.BaseURL+"/quota/approve?"+values.Encode()) != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.cfg.Service.FailQuotaRequest(ctx, nexus.SystemPrincipal(a.AccountID), a.Month, a.ID)
			gateError(w, 502, "mail_unavailable")
			return
		}
	}
	gateJSON(w, 202, publicQuotaRequest(a))
}
func (h *QuotaHandler) poll(w http.ResponseWriter, r *http.Request) {
	p, ok := h.actor(w, r)
	if !ok {
		return
	}
	p, ok = h.target(w, r, p, ids.Account(r.URL.Query().Get("account_id")))
	if !ok {
		return
	}
	id := r.PathValue("id")
	month, ok := quotaRequestMonth(id)
	if !ok {
		gateError(w, 404, "not_found")
		return
	}
	a, err := h.cfg.Service.QuotaRequest(r.Context(), p, month, id)
	if err != nil {
		gateError(w, 404, "not_found")
		return
	}
	gateJSON(w, 200, publicQuotaRequest(a))
}

var quotaPage = approvalPage("quota", "월간 토큰 증액 승인", `<span class="badge">월간 토큰 증액 승인</span><h1>월간 토큰 증액 승인</h1><dl><div><dt>계정</dt><dd><code>{{.AccountID}}</code></dd></div><div><dt>적용 월</dt><dd>{{.Month}} (한국시간)</dd></div><div><dt>기존 한도</dt><dd>{{.PreviousLimit}} 토큰</dd></div><div><dt>증액</dt><dd>{{.Amount}} 토큰</dd></div><div><dt>최종 한도</dt><dd>{{.NewLimit}} 토큰</dd></div><div><dt>만료</dt><dd>{{.ExpiresAt}}</dd></div></dl><p class="muted">증액은 당월에만 적용합니다. 수퍼 관리자만 승인하세요. 대화 요청은 승인이 아니며 이 승인도 세션·위임 한도를 변경하지 않습니다. 다른 증액량은 새 요청으로 별도 승인해야 합니다.</p><form method="post"><button class="approve" name="decision" value="approve">이 정확한 증액 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`+approvalSecurityNote)

func (h *QuotaHandler) decide(w http.ResponseWriter, r *http.Request) {
	id, token := r.URL.Query().Get("id"), r.URL.Query().Get("t")
	month, ok := quotaRequestMonth(id)
	account, err := ids.ParseAccount(r.URL.Query().Get("account_id"))
	if !ok || err != nil || len(token) != 68 || !strings.HasPrefix(token, "qap_") {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	p := nexus.SystemPrincipal(account)
	a, err := h.cfg.Service.QuotaRequest(r.Context(), p, month, id)
	if err != nil || a.Status != "pending" || a.ApprovalHash != Verifier(token) {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	w.Header().Set("Content-Security-Policy", approvalPageCSP)
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = quotaPage.Execute(w, a)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.cfg.BaseURL {
		gateError(w, 403, "forbidden")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.ParseForm() != nil || len(r.PostForm["decision"]) != 1 {
		gateError(w, 400, "invalid_request")
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		gateError(w, 400, "invalid_request")
		return
	}
	a, err = h.cfg.Service.DecideQuotaRequest(r.Context(), p, month, id, Verifier(token), decision == "approve")
	if err != nil {
		gateError(w, 409, "stale_or_expired")
		return
	}
	gateJSON(w, 200, publicQuotaRequest(a))
}
