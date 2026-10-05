package gate

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/redact"
)

// VerificationMailer must deliver privately; log mailers must not be used.
type VerificationMailer interface {
	SendVerification(context.Context, string, string) error
}
type EnrolmentConfig struct {
	Store      *PostgresCredentials
	BaseURL    string
	Allow      []string // exact addresses or domains; empty means disabled
	OwnerEmail string   // when set, only owner plus email-approved admissions
	OwnerOnly  bool     // strict: ignore all admitted-user rows
	OwnerCode  bool     // NEXUS_OWNER_CODE: serve POST /v1/enrol/code (operator owner codes)
	Audit      *Audit   // optional; owner-code redemptions are recorded (enrolment id only)
	Mailer     VerificationMailer
	AdminToken string // explicit bearer only; never trust a proxy's loopback address
	Clock      func() time.Time
}
type EnrolmentHandler struct {
	cfg EnrolmentConfig
	mux *http.ServeMux
}

func NewEnrolmentHandler(cfg EnrolmentConfig) (*EnrolmentHandler, error) {
	u, err := url.Parse(cfg.BaseURL)
	if cfg.Store == nil || cfg.Mailer == nil || len(cfg.Allow) == 0 || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("gate: invalid enrolment configuration")
	}
	if cfg.AdminToken != "" && len(cfg.AdminToken) < 32 {
		return nil, errors.New("gate: admin token must have at least 32 bytes")
	}
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if (cfg.OwnerOnly && cfg.OwnerEmail == "") || (cfg.OwnerEmail != "" && (!validEmail(cfg.OwnerEmail) || len(cfg.Allow) != 1 || strings.ToLower(strings.TrimSpace(cfg.Allow[0])) != cfg.OwnerEmail)) {
		return nil, errors.New("gate: invalid owner policy")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	allow := make([]string, 0, len(cfg.Allow))
	for _, v := range cfg.Allow {
		v = strings.ToLower(strings.TrimSpace(v))
		if strings.Contains(v, "@") {
			if !validEmail(v) {
				return nil, errors.New("gate: invalid allowlist")
			}
		} else if !validEmail("user@"+v) || !strings.Contains(v, ".") {
			return nil, errors.New("gate: invalid allowlist")
		}
		allow = append(allow, v)
	}
	cfg.Allow = allow
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	h := &EnrolmentHandler{cfg: cfg, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /v1/enrol/policy", func(w http.ResponseWriter, r *http.Request) {
		gateJSON(w, 200, map[string]any{"restricted": true, "approval": "email_button"})
	})
	h.mux.HandleFunc("POST /v1/enrol", h.start)
	h.mux.HandleFunc("POST /v1/enrol/code", h.redeemOwnerCode)
	h.mux.HandleFunc("GET /v1/enrol/{id}", h.poll)
	h.mux.HandleFunc("GET /v1/enrol/{id}/key", h.claim)
	h.mux.HandleFunc("GET /v1/enrol/{id}/session", h.claim)
	h.mux.HandleFunc("GET /enrol/verify", h.verify)
	h.mux.HandleFunc("POST /enrol/verify", h.verify)
	h.mux.HandleFunc("POST /v1/admin/revoke", h.revoke)
	return h, nil
}
func (h *EnrolmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second))
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	// same-origin (decision 2026-10-04): with no-referrer a browser form POST carries
	// "Origin: null", which the Origin check refuses. The token URL still never
	// leaves this origin.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}
func validEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n\t ") || !isASCII(s) {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && strings.Contains(s, "@")
}
func (h *EnrolmentHandler) allowed(ctx context.Context, email string) bool {
	if h.cfg.OwnerEmail != "" {
		if email == h.cfg.OwnerEmail {
			return true
		}
		if h.cfg.OwnerOnly {
			return false
		}
		ok, err := h.cfg.Store.Admitted(ctx, h.cfg.OwnerEmail, email)
		return err == nil && ok
	}
	for _, entry := range h.cfg.Allow {
		if email == entry || (!strings.Contains(entry, "@") && strings.HasSuffix(email, "@"+entry)) {
			return true
		}
	}
	return false
}
func gateJSON(w http.ResponseWriter, code int, out any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(out)
}
func gateError(w http.ResponseWriter, code int, label string) {
	gateJSON(w, code, map[string]string{"error": label})
}
func gateDecode(w http.ResponseWriter, r *http.Request, out any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		return nexus.ErrInvalid
	}
	if _, _, err = redact.JSON(raw); err != nil {
		return nexus.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return nexus.ErrInvalid
	}
	return nil
}
func bearer(r *http.Request) string {
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return ""
	}
	v := strings.Fields(h[0])
	if len(v) != 2 || !strings.EqualFold(v[0], "Bearer") || len(v[1]) < 24 || len(v[1]) > 4096 {
		return ""
	}
	return v[1]
}
func (h *EnrolmentHandler) start(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if gateDecode(w, r, &req) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) {
		gateError(w, 400, "invalid_request")
		return
	}
	if !h.allowed(r.Context(), req.Email) {
		gateError(w, 403, "enrol_not_allowed")
		return
	}
	e, poll, verify, err := h.cfg.Store.BeginEnrolment(r.Context(), req.Email, h.cfg.Clock())
	if errors.Is(err, nexus.ErrLimit) {
		w.Header().Set("Retry-After", "1800")
		gateError(w, 429, "rate_limited")
		return
	}
	if err != nil {
		gateError(w, 503, "unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if h.cfg.Mailer.SendVerification(ctx, req.Email, h.cfg.BaseURL+"/enrol/verify?t="+url.QueryEscape(verify)) != nil {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = h.cfg.Store.CancelEnrolment(cleanup, e.ID)
		gateError(w, 502, "mail_unavailable")
		return
	}
	gateJSON(w, 202, map[string]any{"enrolment_id": e.ID, "poll_token": poll, "status": "pending_verification", "expires_at": e.Expires, "next": map[string]any{"url": h.cfg.BaseURL + "/v1/enrol/" + e.ID, "method": "GET", "poll_interval_seconds": 5, "user_message": req.Email + "로 보낸 메일의 승인 버튼을 눌러 주세요. 30분 안에 승인해야 합니다."}})
}

// OwnerCodeNoticeMailer tells the owner, after the fact, that owner
// credentials were issued through an operator code. The mail has no code or link.
type OwnerCodeNoticeMailer interface {
	SendOwnerCodeNotice(context.Context, string) error
}

// redeemOwnerCode is the mail-free owner bootstrap: a code printed by the
// operator's `nexus enrol-owner` becomes an approved enrolment for the
// configured owner and returns a poll token for the normal one-shot claims.
// Without a configured owner there is nothing to redeem. The code travels in
// the body only, so it never reaches URLs or access logs.
func (h *EnrolmentHandler) redeemOwnerCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !h.cfg.OwnerCode || h.cfg.OwnerEmail == "" || gateDecode(w, r, &req) != nil {
		gateError(w, 404, "not_found")
		return
	}
	e, poll, err := h.cfg.Store.RedeemOwnerCode(r.Context(), h.cfg.OwnerEmail, strings.TrimSpace(req.Code), h.cfg.Clock())
	if err != nil {
		gateError(w, 404, "not_found")
		return
	}
	outcome := "credentials_issuable"
	if notice, ok := h.cfg.Mailer.(OwnerCodeNoticeMailer); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		if notice.SendOwnerCodeNotice(ctx, h.cfg.OwnerEmail) != nil {
			outcome = "credentials_issuable_notice_failed"
		}
		cancel()
	}
	if h.cfg.Audit != nil {
		h.cfg.Audit.Write(AuditEvent{Type: "owner_code_redeemed", RequestID: e.ID, Established: AuditEstablished{Outcome: outcome}})
	}
	gateJSON(w, 200, map[string]any{"enrolment_id": e.ID, "poll_token": poll, "status": "verified", "expires_at": e.Expires})
}
func (h *EnrolmentHandler) poll(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if token == "" {
		gateError(w, 404, "not_found")
		return
	}
	e, err := h.cfg.Store.PollEnrolment(r.Context(), r.PathValue("id"), token)
	if err != nil || !h.allowed(r.Context(), e.Email) {
		gateError(w, 404, "not_found")
		return
	}
	status := "pending_verification"
	out := map[string]any{"enrolment_id": e.ID, "expires_at": e.Expires}
	if !h.cfg.Clock().Before(e.Expires) {
		status = "expired"
	} else if e.Approved {
		status = "verified"
		if e.KeyTaken {
			status = "key_taken"
		}
		out["account_id"] = e.Account
		out["key_taken"] = e.KeyTaken
		out["session_taken"] = e.LoginTaken
		out["key_url"] = h.cfg.BaseURL + "/v1/enrol/" + e.ID + "/key"
		out["session_url"] = h.cfg.BaseURL + "/v1/enrol/" + e.ID + "/session"
		out["warning"] = "Fetch each credential once, directly into secure local storage. Never print it. No package or signed delegation is provided by this endpoint."
	}
	out["status"] = status
	gateJSON(w, 200, out)
}
func (h *EnrolmentHandler) verify(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	if len(t) != 68 || !strings.HasPrefix(t, "vfy_") {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	// Mail scanners may GET links. Only an explicit form submission grants access.
	w.Header().Set("Content-Security-Policy", approvalPageCSP)
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, enrolVerifyHTML)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.cfg.BaseURL {
		gateError(w, 403, "forbidden")
		return
	}
	e, err := h.cfg.Store.EnrolmentByVerify(r.Context(), t)
	if err != nil || !h.cfg.Clock().Before(e.Expires) || !h.allowed(r.Context(), e.Email) {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	if _, err = h.cfg.Store.ApproveEnrolment(r.Context(), t, h.cfg.Clock()); err != nil {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, enrolDoneHTML)
}
func (h *EnrolmentHandler) claim(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if token == "" {
		gateError(w, 404, "not_found")
		return
	}
	// Go's GET patterns also match HEAD. A HEAD must never consume a secret.
	if r.Method != "GET" {
		gateError(w, 405, "method_not_allowed")
		return
	}
	e, err := h.cfg.Store.PollEnrolment(r.Context(), r.PathValue("id"), token)
	if err != nil || !h.allowed(r.Context(), e.Email) {
		gateError(w, 404, "not_found")
		return
	}
	kind := "licence"
	if strings.HasSuffix(r.URL.Path, "/session") {
		kind = "login"
	}
	c, secret, err := h.cfg.Store.ClaimEnrolment(r.Context(), r.PathValue("id"), token, kind, h.cfg.Clock())
	if errors.Is(err, ErrAlreadyFetched) {
		gateError(w, 410, "already_fetched")
		return
	}
	if err != nil {
		gateError(w, 404, "not_found")
		return
	}
	if kind == "licence" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, secret+"\n")
		return
	}
	gateJSON(w, 200, map[string]any{"session_token": secret, "expires_at": c.Expires, "email": c.Email, "account_id": c.Account})
}
func (h *EnrolmentHandler) revoke(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if h.cfg.AdminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.AdminToken)) != 1 {
		gateError(w, 403, "not_operator")
		return
	}
	var req struct {
		Verifier string `json:"verifier"`
	}
	if gateDecode(w, r, &req) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	if err := h.cfg.Store.RevokeCredential(r.Context(), req.Verifier); err != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	gateJSON(w, 200, map[string]bool{"revoked": true})
}

// ValidateHandler issues a short lease from BOTH credentials, never from request
// metadata. Errors are not reflected, and it grants no root or execution rights.
func ValidateHandler(store CredentialStore) http.Handler {
	return ValidateHandlerWithWake(store, nil)
}

// ValidateHandlerWithWake binds a session hint through normal Nexus auth. A
// caller-supplied session header alone never grants access to another mailbox.
func ValidateHandlerWithWake(store CredentialStore, service *nexus.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			gateError(w, 405, "method_not_allowed")
			return
		}
		token := bearer(r)
		if token == "" {
			gateError(w, 401, "unauthenticated")
			return
		}
		now := time.Now()
		entry, admission := now, time.Duration(-1)
		if pt, ok := publicTimingFrom(r.Context()); ok {
			entry, admission = pt.start, pt.admission
		}
		status := "invalid"
		var expires int64
		if store != nil {
			c, err := store.LookupCredential(r.Context(), Verifier(token))
			if err == nil && validCredential(c) && c.Kind == "licence" {
				switch {
				case c.Revoked:
					status = "revoked"
				case !now.Before(c.Expires):
					status = "expired"
				default:
					status = "session_expired"
					logins := r.Header.Values("X-Newtype-Login")
					if len(logins) == 1 && len(logins[0]) >= 24 && len(logins[0]) <= 4096 {
						l, err := store.LookupCredential(r.Context(), Verifier(logins[0]))
						if err == nil && validCredential(l) && l.Kind == "login" && !l.Revoked && now.Before(l.Expires) && l.Account == c.Account {
							status = "valid"
							expires = 35
							for _, end := range []time.Time{c.Expires, l.Expires} {
								if n := int64(end.Sub(now) / time.Second); n < expires {
									expires = n
								}
							}
						}
					}
				}
			}
		}
		if status == "valid" && service != nil {
			actor, err := (NexusAuth{Store: store, Service: service}).Authenticate(r)
			if err == nil && service.WakeHint(r.Context(), actor) {
				w.Header().Set(nexus.WakeHeader, "1")
			}
		}
		auth := time.Since(now)
		gateJSON(w, 200, map[string]any{"status": status, "expires_in": expires, "request_id": ids.New(ids.KindAction)})
		// Debug only: where a lease validate spends its time (all DB here).
		slog.Default().Debug("validate timing", "admission_db", ms(admission), "auth_db", ms(auth), "total", ms(time.Since(entry)), "outcome", status)
	})
}
