package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/mcpauth"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus"
)

// remoteMCPOrigins may call /mcp from a browser; server-side clients send no
// Origin and pass.
var remoteMCPOrigins = []string{"https://claude.ai", "https://claude.com"}

// newRemoteMCP builds the remote MCP endpoint (docs/nmcp-remote-endpoint.md):
// OAuth state in Postgres, consent by CLI code always and by mail when the
// approvals admin client is configured, the request_approval mail fallback
// through the same client. inner is Nexus's own handler (in-process calls).
func newRemoteMCP(ctx context.Context, cfg nexusserver.Config, pool *pgxpool.Pool, service *nexus.Service, auth gate.CredentialStore, credentials *gate.PostgresCredentials, inner http.Handler) (*mcpauth.Endpoint, error) {
	store := mcpauth.NewPostgresStore(pool)
	var version int
	if pool.QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='mcp_oauth'`).Scan(&version) != nil || version != mcpauth.SchemaVersion {
		return nil, errors.New("nexus: mcp oauth schema missing; run explicit migration")
	}
	server := &mcpauth.Server{Issuer: cfg.MCPIssuer, Store: store, OwnerEmail: cfg.OwnerEmail, AccountForEmail: credentials.AccountForEmail,
		Authenticate: nexusserver.PersonAuth(service, auth), AccountLive: accountLive(credentials, auth)}
	conn := &mcpauth.Connector{Store: store, Service: service, Handler: inner, Version: "nexus"}
	if cfg.DefaultModelApprovals != "" && cfg.OwnerEmail != "" {
		approvals, err := gate.NewChangeAdminClient(cfg.DefaultModelApprovals, cfg.DefaultModelApprovalsToken, nil)
		if err != nil {
			return nil, errors.New("nexus: invalid approvals client for the remote MCP endpoint")
		}
		server.Approvals = approvals // the mail-consent switch itself is a person setting (/v1/mcp/settings), off by default
		conn.Mail = &mcpauth.MailApprovals{Approvals: approvals, Owner: cfg.OwnerEmail}
	}
	return mcpauth.NewEndpoint(server, conn, remoteMCPOrigins), nil
}

// accountLive: the account still holds a live licence and a live login, both
// admitted by the server's credential policy (owner-only when configured).
func accountLive(credentials *gate.PostgresCredentials, auth gate.CredentialStore) func(context.Context, ids.Account) bool {
	owner, _ := auth.(*gate.OwnerCredentials)
	return func(ctx context.Context, account ids.Account) bool {
		live, err := credentials.LiveCredentials(ctx, account, time.Now())
		if err != nil {
			return false
		}
		licence, login := false, false
		for _, c := range live {
			if owner != nil && !owner.Admits(ctx, c) {
				continue
			}
			licence = licence || c.Kind == "licence"
			login = login || c.Kind == "login"
		}
		return licence && login
	}
}
