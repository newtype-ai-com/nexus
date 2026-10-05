package nexusserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

// NewHandler leaves model/tool execution disabled until a metered runner is
// explicitly configured. No shell or arbitrary upstream is exposed by default.
func NewHandler(service *nexus.Service, credentials gate.CredentialStore, ready func(context.Context) error) (http.Handler, error) {
	return NewHandlerWithEnrolment(service, credentials, ready, nil)
}

func NewHandlerWithEnrolment(service *nexus.Service, credentials gate.CredentialStore, ready func(context.Context) error, enrolment http.Handler) (http.Handler, error) {
	return NewHandlerWithOptions(service, credentials, ready, enrolment, HandlerOptions{})
}

// HandlerOptions are optional server policies.
type HandlerOptions struct {
	// ModelScope limits roots asking for model:<name> (the relayed default
	// model: owner and designated users only, gate.ModelScopeAllowed).
	ModelScope func(*http.Request, nexus.Principal, string) bool
}

func NewHandlerWithOptions(service *nexus.Service, credentials gate.CredentialStore, ready func(context.Context) error, enrolment http.Handler, opts HandlerOptions) (http.Handler, error) {
	if service == nil || credentials == nil || ready == nil {
		return nil, nexus.ErrInvalid
	}
	// The owner of an owner-filtered store may ask for an unlimited root.
	var owner func(*http.Request, nexus.Principal) bool
	if oc, ok := credentials.(*gate.OwnerCredentials); ok {
		owner = gate.OwnerPersonFunc(credentials, oc.Owner())
	}
	api, err := httpapi.New(httpapi.Config{
		Service: service, Authenticate: withInProcess(refuseMCPTokens(executorOrGate(service, gate.NexusAuth{Store: credentials, Service: service}.Authenticate))),
		Reauthenticate: withInProcess(refuseMCPTokens(gate.NexusAuth{Store: credentials, Service: service}.Reauthenticate)),
		Durable:        true, Actions: map[string]int64{},
		Run:         func(context.Context, string, json.RawMessage) error { return nexus.ErrForbidden },
		OwnerPerson: owner,
		ModelScope:  opts.ModelScope,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/delegation/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		keys := service.DelegationKeys()
		if len(keys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if ready(ctx) != nil {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"ok":false}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "nexus_schema": pgstore.SchemaVersion, "gate_schema": gate.CredentialSchemaVersion, "enrolment_schema": gate.EnrolmentSchemaVersion})
	})
	mux.HandleFunc("GET /llm.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Newtype Nexus API. Use Bearer licence plus X-Newtype-Login. Optional email enrolment: GET /v1/enrol/policy then POST /v1/enrol with email. Fetch each credential once into secure storage; never print credentials, poll tokens or mail approval links. POST /v1/validate checks a short lease. Human-authenticated POST /v1/requests issues a local task grant; it is not a passkey signature. Remote execution and package installation are not enabled.\n"))
	})
	mux.Handle("/v1/validate", gate.ValidateHandlerWithWake(credentials, service))
	if enrolment != nil {
		for _, path := range []string{"/v1/enrol", "/v1/enrol/", "/enrol/verify", "/v1/admin/revoke", "/v1/device", "/v1/device/", "/device/confirm", "/v1/users/requests", "/users/approve", "/v1/quota", "/v1/quota/", "/quota/approve"} {
			mux.Handle(path, enrolment)
		}
	}
	mux.Handle("/", api)
	return mux, nil
}

func HTTPServer(port string, handler http.Handler) *http.Server {
	return HTTPServerOn("", port, handler)
}

// HTTPServerOn binds host (empty: all interfaces) and port.
func HTTPServerOn(host, port string, handler http.Handler) *http.Server {
	return &http.Server{Addr: net.JoinHostPort(host, port), Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
}

// executorOrGate authenticates an nte_ executor bearer against Nexus' own
// hashed executor credentials (audience-limited by httpapi) and everything
// else through Gate. A request carrying any other identity header with an
// nte_ bearer is refused.
func executorOrGate(service *nexus.Service, gateAuth func(*http.Request) (nexus.Principal, error)) func(*http.Request) (nexus.Principal, error) {
	return func(r *http.Request) (nexus.Principal, error) {
		values := r.Header.Values("Authorization")
		if len(values) == 1 && strings.HasPrefix(values[0], "Bearer "+nexus.ExecutorTokenPrefix) {
			if r.Header.Get("X-Newtype-Session") != "" || r.Header.Get("X-Newtype-Login") != "" {
				return nexus.Principal{}, nexus.ErrForbidden
			}
			return service.AuthenticateExecutor(r.Context(), strings.TrimPrefix(values[0], "Bearer "))
		}
		return gateAuth(r)
	}
}
