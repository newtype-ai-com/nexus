package gate

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
)

type UserAdmissionMailer interface {
	SendUserAdmission(context.Context, string, string, string) error
}

// UserAdmissionHandler accepts requests from the owner's authenticated local
// session or person, but only a private email POST can approve the exact target.
type UserAdmissionHandler struct {
	enrol *EnrolmentHandler
	owner string
	auth  func(*http.Request) (nexus.Principal, error)
	mux   *http.ServeMux
}

func NewUserAdmissionHandler(cfg EnrolmentConfig, auth func(*http.Request) (nexus.Principal, error)) (*UserAdmissionHandler, error) {
	_, hasMailer := cfg.Mailer.(UserAdmissionMailer)
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if !ValidOwnerEmail(cfg.OwnerEmail) || auth == nil || !hasMailer {
		return nil, nexus.ErrInvalid
	}
	enrol, err := NewEnrolmentHandler(cfg)
	if err != nil {
		return nil, err
	}
	h := &UserAdmissionHandler{enrol: enrol, owner: enrol.cfg.OwnerEmail, auth: auth, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /v1/users/requests", h.start)
	h.mux.HandleFunc("GET /users/approve", h.decide)
	h.mux.HandleFunc("POST /users/approve", h.decide)
	return h, nil
}
func (h *UserAdmissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
func (h *UserAdmissionHandler) start(w http.ResponseWriter, r *http.Request) {
	p, err := h.auth(r)
	if err != nil {
		gateError(w, 401, "unauthenticated")
		return
	}
	// The service authenticates account/session ownership. The original licence
	// independently identifies the administrator; a model-supplied email cannot.
	c, err := h.enrol.cfg.Store.LookupCredential(r.Context(), Verifier(bearer(r)))
	if err != nil || c.Kind != "licence" || c.Revoked || !h.enrol.cfg.Clock().Before(c.Expires) || c.Email != h.owner || c.Account != p.AccountID || (p.Kind != nexus.PrincipalUser && p.Kind != nexus.PrincipalSession) {
		gateError(w, 403, "forbidden")
		return
	}
	var req struct {
		Email  string `json:"email"`
		Client string `json:"client_event_id"`
	}
	if gateDecode(w, r, &req) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	a, token, err := h.enrol.cfg.Store.BeginUserAdmission(r.Context(), p.AccountID, h.owner, req.Email, req.Client, h.enrol.cfg.Clock())
	if err != nil {
		switch err {
		case nexus.ErrInvalid:
			gateError(w, 400, "invalid_request")
		case nexus.ErrLimit:
			w.Header().Set("Retry-After", "3600")
			gateError(w, 429, "rate_limited")
		default:
			gateError(w, 409, "request_conflict")
		}
		return
	}
	if token != "" {
		if h.enrol.cfg.Mailer.(UserAdmissionMailer).SendUserAdmission(r.Context(), h.owner, a.Email, h.enrol.cfg.BaseURL+"/users/approve?t="+url.QueryEscape(token)) != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.enrol.cfg.Store.FailUserAdmission(ctx, a.ID)
			gateError(w, 502, "mail_unavailable")
			return
		}
	}
	gateJSON(w, 202, a)
}

var admissionPage = approvalPage("admission", "Newtype 사용자 추가 승인", `<span class="badge">사용자 추가 승인</span><h1>사용자 추가 승인</h1><dl><div><dt>추가할 사용자</dt><dd>{{.Email}}</dd></div><div><dt>만료</dt><dd>{{.Expires.Format "2006-01-02 15:04 MST"}}</dd></div></dl><p>직접 요청한 주소인지 확인하세요. 이 승인은 가입만 허용하며 관리자 권한은 부여하지 않습니다. 추가 사용자는 자신의 메일 인증을 거쳐야 합니다.</p><form method="post"><button class="approve" name="decision" value="approve">이 사용자 추가 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`+approvalSecurityNote)

func (h *UserAdmissionHandler) decide(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if len(token) != 68 || !strings.HasPrefix(token, "uap_") {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	a, err := h.enrol.cfg.Store.UserAdmissionByToken(r.Context(), h.owner, token, h.enrol.cfg.Clock())
	if err != nil {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	w.Header().Set("Content-Security-Policy", approvalPageCSP)
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = admissionPage.Execute(w, a)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.enrol.cfg.BaseURL {
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
	if h.enrol.cfg.Store.DecideUserAdmission(r.Context(), h.owner, token, decision == "approve", h.enrol.cfg.Clock()) != nil {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	gateJSON(w, 200, map[string]string{"status": "decision_recorded"})
}
