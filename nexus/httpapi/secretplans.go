package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// executorAudience is everything an nte_ credential may call (design v4 §6/A2).
func executorAudience(method, path string) bool {
	switch {
	case method == "POST" && path == "/v1/secret-plans":
		return true
	case method == "GET" && path == "/v1/secret-plans":
		return true // lookup by ?attempt=
	case strings.HasPrefix(path, "/v1/secret-plans/run_"):
		rest := strings.TrimPrefix(path, "/v1/secret-plans/")
		parts := strings.Split(rest, "/")
		switch {
		case len(parts) == 1 && method == "GET":
			return true
		case len(parts) == 2 && method == "POST" && (parts[1] == "release" || parts[1] == "finish" || parts[1] == "receipt"):
			return true
		}
	case method == "POST" && path == "/v1/custody/approvals":
		return true // request the plan approval (exec:secret-plan only, enforced below)
	case method == "GET" && strings.HasPrefix(path, "/v1/custody/approvals/apr_") && strings.Count(path, "/") == 4:
		return true
	}
	return false
}

// ExecutorCredentialVersion is the wire version of an issue response.
const ExecutorCredentialVersion = "newtype.executor-credential/1"

func (a *API) registerSecretPlans() {
	// Person-only issue of one nte_ executor credential bound to the exact
	// session and delegation. The token is in this one response only (never
	// stored, never readable again); the response is not cacheable.
	a.mux.HandleFunc("POST /v1/executor-credentials", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Session    ids.Session    `json:"session"`
			Delegation ids.Delegation `json:"delegation"`
			TTLSeconds int64          `json:"ttl_seconds"`
		}
		if principal(r).Kind != nexus.PrincipalUser {
			fail(w, nexus.ErrForbidden)
			return
		}
		if decode(w, r, &req) != nil || ids.Check(ids.KindSession, string(req.Session)) != nil ||
			ids.Check(ids.KindDelegation, string(req.Delegation)) != nil ||
			req.TTLSeconds <= 0 || req.TTLSeconds > int64(nexus.ExecutorMaxTTL/time.Second) {
			fail(w, nexus.ErrInvalid)
			return
		}
		c, token, err := a.cfg.Service.IssueExecutorCredential(r.Context(), principal(r), req.Session, req.Delegation, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		write(w, 201, map[string]any{"version": ExecutorCredentialVersion, "id": c.ID, "account": c.AccountID, "session": c.SessionID,
			"delegation": c.Delegation, "created_at": c.CreatedAt.UTC().Format(time.RFC3339), "expires_at": c.ExpiresAt.UTC().Format(time.RFC3339), "token": token})
	})
	a.mux.HandleFunc("POST /v1/executor-credentials/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if principal(r).Kind != nexus.PrincipalUser {
			fail(w, nexus.ErrForbidden)
			return
		}
		if !strings.HasPrefix(id, "exc_") || len(id) > 64 {
			fail(w, nexus.ErrInvalid)
			return
		}
		if err := a.cfg.Service.RevokeExecutorCredential(r.Context(), principal(r), id); err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"id": id, "revoked": true})
	})
	a.mux.HandleFunc("POST /v1/secret-plans", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Plan     string       `json:"plan"`
			Approval ids.Approval `json:"approval_id"`
		}
		// The plan is public canonical JSON: decode strictly but do not run the
		// credential-pattern scrubber over it (it carries hashes/paths only).
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 80<<10))
		if err != nil || strictJSON(raw, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		if _, err := ids.ParseApproval(string(req.Approval)); err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.StartSecretPlan(r.Context(), principal(r), []byte(req.Plan), req.Approval)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 201, out)
	})
	a.mux.HandleFunc("GET /v1/secret-plans", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) != 1 || len(q["attempt"]) != 1 {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.SecretPlanRunByAttempt(r.Context(), principal(r), q.Get("attempt"))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("GET /v1/secret-plans/{run}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseRun(r.PathValue("run"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.SecretPlanRun(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("POST /v1/secret-plans/{run}/release", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseRun(r.PathValue("run"))
		var req struct {
			Role string `json:"role"`
		}
		if err != nil || decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.ReleaseSecretPlanRole(r.Context(), principal(r), id, req.Role)
		if err != nil {
			fail(w, err)
			return
		}
		defer clear(out.Value)
		body := map[string]any{"version": out.Version, "run_id": out.RunID, "role": out.Role, "authorised_until": out.AuthorisedUntil}
		if out.Value != nil {
			body["value_b64"] = base64.StdEncoding.EncodeToString(out.Value)
		}
		write(w, 200, body)
	})
	// Signed run receipt (schema ruling §4): bootstrap before any release,
	// dispatch after every release. Non-consuming; nothing is released.
	a.mux.HandleFunc("POST /v1/secret-plans/{run}/receipt", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseRun(r.PathValue("run"))
		var req struct {
			Op        string `json:"op"`
			Challenge string `json:"challenge"`
		}
		if err != nil || decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		jws, err := a.cfg.Service.SecretPlanReceipt(r.Context(), principal(r), id, req.Op, req.Challenge)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"version": "newtype.run-receipt-response/1", "receipt": jws})
	})
	a.mux.HandleFunc("POST /v1/secret-plans/{run}/finish", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseRun(r.PathValue("run"))
		var req struct {
			Outcome string `json:"outcome"`
		}
		if err != nil || decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.FinishSecretPlan(r.Context(), principal(r), id, req.Outcome)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
}

// strictJSON decodes one flat object: unknown fields, duplicate keys and
// trailing data are refused (no credential scrubber: the body is public).
func strictJSON(raw []byte, dst any) error {
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return nexus.ErrInvalid
	}
	t := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := t.Token(); err != nil || tok != json.Delim('{') {
		return nexus.ErrInvalid
	}
	seen := map[string]bool{}
	for t.More() {
		tok, err := t.Token()
		k, ok := tok.(string)
		if err != nil || !ok || seen[k] {
			return nexus.ErrInvalid
		}
		seen[k] = true
		var skip json.RawMessage
		if t.Decode(&skip) != nil {
			return nexus.ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return nexus.ErrInvalid
	}
	return nil
}
