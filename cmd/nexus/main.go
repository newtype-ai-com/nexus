// Command nexus runs the Nexus server (serve, migrate, provision, approvals,
// enrol-owner) against a PostgreSQL database.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/mcpauth"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/internal/release"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin); err != nil {
		// No raw SQL/network errors, DSNs, request bodies or tokens in logs.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, input io.Reader) error {
	if len(args) > 0 && args[0] == "call-budget-init" {
		return runModelCallBudgetInit(args[1:])
	}
	if len(args) > 0 && args[0] == "call-budget-status" {
		return runModelCallBudgetStatus(args[1:], os.Stdout)
	}
	if len(args) > 1 && args[0] == "migrate" {
		// The only multi-argument form: migrate --dsn-fd N (pipe-only DSN).
		return runMigrateDSNFD(ctx, args, os.Environ(), readDSNFD)
	}
	mode := "serve"
	if len(args) == 1 {
		mode = args[0]
	} else if len(args) > 1 {
		return errors.New("usage: nexus [serve|migrate|provision|approvals|enrol-owner]")
	}
	if mode == "approvals" {
		return runApprovals(ctx, os.Getenv)
	}
	if mode != "serve" && mode != "migrate" && mode != "provision" && mode != "enrol-owner" {
		return errors.New("usage: nexus [serve|migrate|provision|approvals|enrol-owner]")
	}
	cfg, err := nexusserver.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	store, err := pgstore.Open(ctx, storeConfig(cfg))
	if err != nil {
		return fmt.Errorf("nexus: database connection failed (%s)", pgstore.ConnectionStage(err))
	}
	defer store.Close()
	credentials := gate.NewPostgresCredentials(store.Pool())
	var authCredentials gate.CredentialStore = credentials
	if cfg.OwnerEmail != "" {
		authCredentials, err = gate.NewOwnerCredentialsWithPolicy(credentials, cfg.OwnerEmail, cfg.OwnerOnly)
		if err != nil {
			return errors.New("nexus: invalid owner configuration")
		}
	}
	if mode == "migrate" {
		for _, step := range []struct {
			name string
			run  func() error
		}{
			{"ensure schema", func() error { return store.EnsureSchema(ctx, cfg.Schema) }},
			{"nexus", func() error { return store.Migrate(ctx) }},
			{"credentials", func() error { return credentials.Migrate(ctx) }},
			{"enrolments", func() error { return credentials.MigrateEnrolments(ctx) }},
			{"mcp oauth", func() error { return mcpauth.NewPostgresStore(store.Pool()).Migrate(ctx) }},
			{"secure schema", func() error { return nexusserver.SecureSchema(ctx, store.Pool(), cfg.Schema) }},
		} {
			if step.run() != nil {
				// Identify the stage, never expose raw SQL errors or credentials.
				return fmt.Errorf("nexus: migration failed (%s)", step.name)
			}
		}
		fmt.Println(migrationsComplete)
		return nil
	}
	check := func(ctx context.Context) error {
		var nv, gv int
		if store.Pool().QueryRow(ctx, `SELECT value FROM hub_meta WHERE key='schema'`).Scan(&nv) != nil || nv != pgstore.SchemaVersion {
			return errors.New("nexus schema mismatch")
		}
		if store.Pool().QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='credentials'`).Scan(&gv) != nil || gv != gate.CredentialSchemaVersion {
			return errors.New("gate schema mismatch")
		}
		return credentials.CheckEnrolments(ctx)
	}
	if check(ctx) != nil {
		return errors.New("nexus: schema mismatch; run explicit migration")
	}
	if mode == "provision" {
		// Offline operator boundary, never an HTTP route. JSON has a SHA-256
		// verifier, not a plaintext token. Provisioning requires DB authority.
		var c gate.Credential
		d := json.NewDecoder(io.LimitReader(input, 8193))
		d.DisallowUnknownFields()
		if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
			return errors.New("nexus: invalid credential record")
		}
		if authCredentials.PutCredential(ctx, c) != nil {
			return errors.New("nexus: credential provisioning failed")
		}
		fmt.Println("Credential verifier stored")
		return nil
	}
	if mode == "enrol-owner" {
		return runEnrolOwner(ctx, cfg, credentials, os.Stdout)
	}
	service := nexus.NewService(store, nil)
	if cfg.Sealer != nil {
		service, err = nexus.NewServiceWithSealing(store, nil, cfg.Sealer, cfg.Issuer)
		if err != nil {
			return errors.New("nexus: invalid sealing configuration")
		}
	}
	var enrolment http.Handler
	if cfg.EnrolmentConfig != nil {
		mailer, err := gate.NewResendMailer(cfg.ResendAPIKey, cfg.MailFrom)
		if err != nil {
			return errors.New("nexus: invalid mail configuration")
		}
		ec := *cfg.EnrolmentConfig
		ec.Store = credentials
		ec.Mailer = mailer
		if ec.OwnerCode {
			ownerAudit, auditErr := gate.NewAudit(os.Stderr)
			if auditErr != nil {
				return errors.New("nexus: audit unavailable")
			}
			defer ownerAudit.Close()
			ec.Audit = ownerAudit
		}
		enrolment, err = registrationHandler(cfg, ec, service, authCredentials, mailer)
		if err != nil {
			return err
		}
	}
	// The relayed default model is limited to the owner and designated users
	// (decision 2026-10-05): refused at root issuance and again at the relay.
	var modelAccess *gate.ModelAccess
	var hopts nexusserver.HandlerOptions
	if cfg.ModelConfig != nil {
		path := ""
		if cfg.DefaultModelStore != "" {
			path = filepath.Join(filepath.Dir(cfg.DefaultModelStore), "model-access.json")
		}
		if modelAccess, err = gate.OpenModelAccess(path); err != nil {
			return errors.New("nexus: model access list unavailable")
		}
		hopts.ModelScope = gate.ModelScopeAllowed(authCredentials, cfg.OwnerEmail, modelAccess, cfg.ModelConfig.Models)
	}
	handler, err := nexusserver.NewHandlerWithOptions(service, authCredentials, check, enrolment, hopts)
	if err != nil {
		return errors.New("nexus: invalid server configuration")
	}
	var remoteMCP *mcpauth.Endpoint
	if cfg.MCPIssuer != "" {
		if remoteMCP, err = newRemoteMCP(ctx, cfg, store.Pool(), service, authCredentials, credentials, handler); err != nil {
			return err
		}
		defer remoteMCP.MCP.Close()
		routes := http.NewServeMux()
		remoteMCP.Routes(routes)
		routes.Handle("/", handler)
		handler = routes
	}
	var defaultModel *gate.DefaultModelOperator
	if cfg.ModelConfig != nil {
		mc := *cfg.ModelConfig
		mc.Service, mc.Store, mc.Access = service, authCredentials, modelAccess
		model, modelErr := gate.NewModelHandler(mc)
		if modelErr != nil {
			return errors.New("nexus: invalid model configuration")
		}
		routes := http.NewServeMux()
		if cfg.OwnerEmail != "" {
			// Owner-only status/change of the default model upstream. A stored,
			// sealed operator value replaces the environment bootstrap here.
			dm := gate.DefaultModelConfig{Model: model, Service: service, Store: authCredentials, OwnerEmail: cfg.OwnerEmail, Sealer: cfg.Sealer}
			if cfg.DefaultModelStore != "" {
				if dm.Storage, err = gate.NewFileDefaultModelStore(cfg.DefaultModelStore); err != nil {
					return errors.New("nexus: invalid default model storage")
				}
			}
			if cfg.DefaultModelApprovals != "" {
				if dm.Approvals, err = gate.NewChangeAdminClient(cfg.DefaultModelApprovals, cfg.DefaultModelApprovalsToken, nil); err != nil {
					return errors.New("nexus: invalid default model approvals")
				}
			}
			audit, auditErr := gate.NewAudit(os.Stderr)
			if auditErr != nil {
				return errors.New("nexus: audit unavailable")
			}
			defer audit.Close()
			dm.Audit = audit
			defaultModel, err = gate.NewDefaultModelOperator(ctx, dm)
			if err != nil {
				return errors.New("nexus: stored default model unavailable")
			}
			access, accessErr := gate.NewModelAccessHandler(gate.ModelAccessConfig{Access: modelAccess, Service: service, Store: authCredentials,
				OwnerEmail: cfg.OwnerEmail, AccountForEmail: credentials.AccountForEmail, Audit: audit, Record: operatorRecord(service)})
			if accessErr != nil {
				return errors.New("nexus: invalid model access configuration")
			}
			routes.Handle("/v1/operator/model-access", access)
			routes.Handle("/v1/operator/default-model", defaultModel)
			routes.Handle("/v1/operator/default-model/", defaultModel)
		}
		// Both protocol routes are mounted; only the one matching the current
		// upstream snapshot serves, so an approved protocol change follows.
		routes.Handle("/v1/model/chat/completions", model.ProtocolRoute("chat/completions"))
		routes.Handle("/v1/model/responses", model.ProtocolRoute("responses"))
		routes.Handle("/", handler)
		handler = routes
	}
	// Public, unauthenticated signed client releases (404 while unset); the
	// client verifies the offline signature, so the server is only transport.
	handler = release.Mount(handler, cfg.ReleasesDir)
	handler = credentials.LimitPublicAPI(handler)
	serverCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for serverCtx.Err() == nil {
			_ = store.Listen(serverCtx, service.Notify)
			select {
			case <-serverCtx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	operatorDone := make(chan struct{})
	go func() {
		defer close(operatorDone)
		if defaultModel != nil {
			defaultModel.Run(serverCtx, 10*time.Second)
		}
	}()
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		since := time.Now()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-serverCtx.Done():
				return
			case <-ticker.C:
				cleanup, cancel := context.WithTimeout(serverCtx, 10*time.Second)
				if credentials.CleanupExpiredChallenges(cleanup, time.Now()) != nil && serverCtx.Err() == nil {
					fmt.Fprintln(os.Stderr, "nexus: challenge maintenance failed")
				}
				cancel()
				if remoteMCP != nil {
					remoteMCP.MCP.Sweep(time.Now())
					remoteMCP.Auth.Sweep(serverCtx)
				}
				if _, err := service.Sweep(serverCtx, since, nexus.PresenceGrace, nexus.ArchiveAfter); err != nil && serverCtx.Err() == nil {
					fmt.Fprintln(os.Stderr, "nexus: presence maintenance failed")
				}
			}
		}
	}()
	srv := nexusserver.HTTPServerOn(cfg.BindHost, cfg.Port, handler)
	srv.BaseContext = func(net.Listener) context.Context { return serverCtx }
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()
	fmt.Fprintln(os.Stderr, startupSummary(cfg))
	fmt.Println("Nexus server listening")
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-failed:
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if srv.Shutdown(shutdown) != nil {
		_ = srv.Close()
	}
	<-done
	<-maintenanceDone
	<-operatorDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("nexus: HTTP server failed")
	}
	return nil
}

// storeConfig is the serve/migrate/provision store wiring. SCRAM-only
// authentication follows cfg.DBRequireSCRAM, which ConfigFromEnv turns on for
// every non-development database (BBP-R1): B's later use of the runtime
// password never answers a cleartext/MD5 request, even over verified TLS.
func storeConfig(cfg nexusserver.Config) pgstore.Config {
	return pgstore.Config{
		DSN: cfg.DSN, Schema: cfg.Schema, MaxConns: 8, MinIdleConns: 2, RequireSCRAM: cfg.DBRequireSCRAM,
		Role: cfg.DBRole, StatementTimeoutMS: cfg.DBStatementTimeoutMS, LockTimeoutMS: cfg.DBLockTimeoutMS,
	}
}

// operatorRecord writes an owner's operator change into the ledger of the
// owner's operator seat (the CLI's default seat), as the owner person.
func operatorRecord(service *nexus.Service) func(context.Context, nexus.Principal, string, map[string]any) {
	return func(ctx context.Context, owner nexus.Principal, kind string, payload map[string]any) {
		raw, err := json.Marshal(payload)
		if err != nil {
			return
		}
		if seat, err := service.SessionByName(ctx, owner, "operator"); err == nil && seat != nil {
			_, _ = service.AppendEvents(ctx, owner, seat.ID, []nexus.EventInput{{Source: "user", Kind: kind, Payload: raw}})
		}
	}
}
