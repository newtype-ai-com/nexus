package gate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/nexus"
)

// DeviceHandler uses the same private mail transport and explicit allowlist as
// enrolment. No operator loopback bypass exists behind the Cloudflare proxy.
type DeviceHandler struct {
	enrol *EnrolmentHandler
	mux   *http.ServeMux
}

func NewDeviceHandler(cfg EnrolmentConfig) (*DeviceHandler, error) {
	e, err := NewEnrolmentHandler(cfg)
	if err != nil {
		return nil, err
	}
	h := &DeviceHandler{enrol: e, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /v1/device", h.start)
	h.mux.HandleFunc("POST /v1/device/token", h.token)
	h.mux.HandleFunc("GET /device/confirm", h.confirm)
	h.mux.HandleFunc("POST /device/confirm", h.confirm)
	return h, nil
}
func (h *DeviceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
func (h *DeviceHandler) start(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if gateDecode(w, r, &req) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	key := bearer(r)
	if key == "" {
		gateError(w, 401, "unauthenticated")
		return
	}
	cfg := h.enrol.cfg
	// Check allowlist before sending mail, even for an existing licence.
	c, err := cfg.Store.LookupCredential(r.Context(), Verifier(key))
	if err != nil || !h.enrol.allowed(r.Context(), c.Email) {
		gateError(w, 403, "licence_invalid")
		return
	}
	started, approval, email, err := cfg.Store.BeginDevice(r.Context(), key, cfg.Clock())
	if errors.Is(err, nexus.ErrLimit) {
		w.Header().Set("Retry-After", "600")
		gateError(w, 429, "rate_limited")
		return
	}
	if err != nil {
		gateError(w, 403, "licence_invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if cfg.Mailer.SendVerification(ctx, email, cfg.BaseURL+"/device/confirm?t="+url.QueryEscape(approval)) != nil {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = cfg.Store.CancelDevice(clean, started.Code)
		gateError(w, 502, "mail_unavailable")
		return
	}
	gateJSON(w, 200, map[string]any{"device_code": started.Code, "expires_in": started.ExpiresIn, "interval": started.Interval, "next": map[string]any{"user_message": email + "로 보낸 로그인 메일에서 직접 요청한 로그인인지 확인한 뒤 승인하세요. 10분 안에 승인해야 합니다."}})
}
func (h *DeviceHandler) confirm(w http.ResponseWriter, r *http.Request) {
	link := r.URL.Query().Get("t")
	if len(link) != 68 || !strings.HasPrefix(link, "apv_") {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	w.Header().Set("Content-Security-Policy", approvalPageCSP)
	if r.Method == "GET" || r.Method == "HEAD" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, deviceConfirmHTML)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.enrol.cfg.BaseURL {
		gateError(w, 403, "forbidden")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.ParseForm() != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		gateError(w, 400, "invalid_request")
		return
	}
	if err := h.enrol.cfg.Store.ConfirmDevice(r.Context(), link, decision == "deny", h.enrol.cfg.Clock()); err != nil {
		gateError(w, 404, "unknown_or_expired")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, deviceDoneHTML)
}
func (h *DeviceHandler) token(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"device_code"`
	}
	if gateDecode(w, r, &req) != nil || len(req.Code) != 68 || !strings.HasPrefix(req.Code, "dev_") {
		gateError(w, 400, "invalid_request")
		return
	}
	c, token, err := h.enrol.cfg.Store.ClaimDeviceAllowed(r.Context(), req.Code, h.enrol.cfg.Clock(), func(tx pgx.Tx, email string) bool {
		if h.enrol.cfg.OwnerEmail == "" || email == h.enrol.cfg.OwnerEmail {
			return h.enrol.allowed(r.Context(), email)
		}
		if h.enrol.cfg.OwnerOnly {
			return false
		}
		// Reuse the claim transaction rather than acquiring a second pool slot.
		var allowed bool
		err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM gate_admitted_users WHERE owner_email=$1 AND email=$2)`, h.enrol.cfg.OwnerEmail, email).Scan(&allowed)
		return err == nil && allowed
	})
	if err != nil {
		switch err {
		case ErrDeviceExpired, ErrDevicePending, ErrDeviceSlow, ErrDeviceDenied:
			gateError(w, 400, err.Error())
		default:
			gateError(w, 503, "unavailable")
		}
		return
	}
	gateJSON(w, 200, map[string]any{"session_token": token, "expires_at": c.Expires, "email": c.Email, "account_id": c.Account})
}
