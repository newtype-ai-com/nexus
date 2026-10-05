// Package nexusserver assembles the private Postgres-backed Nexus server.
package nexusserver

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/release"
	"github.com/newtype-ai-com/nexus/seal"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Sealer          *seal.Sealer
	Issuer          string
	ModelConfig     *gate.ModelConfig
	EnrolmentConfig *gate.EnrolmentConfig
	ResendAPIKey    string
	MailFrom        string
	OwnerEmail      string
	OwnerOnly       bool
	// OwnerCode (NEXUS_OWNER_CODE=1) enables the mail-free owner bootstrap:
	// `nexus enrol-owner` and POST /v1/enrol/code. Off: the route is 404.
	OwnerCode            bool
	DSN                  string
	Schema               string
	DBRole               string
	DBStatementTimeoutMS int
	DBLockTimeoutMS      int
	// DBRequireSCRAM makes the store refuse every database authentication
	// except a complete SCRAM-SHA-256 exchange (pgstore.Config.RequireSCRAM),
	// so the runtime password is never sent to a cleartext/MD5 request.
	// NEXUS_DB_REQUIRE_SCRAM: unset = on for every non-development database;
	// "0" is accepted only for the NEXUS_ALLOW_LOCAL_DB loopback exception.
	DBRequireSCRAM bool
	Port           string
	// BindHost is empty (all interfaces, the container default) or a loopback
	// IP literal (for example 127.0.0.1 behind a local reverse proxy).
	BindHost string
	// Operator-changeable default model (docs/default-model-operator.md).
	// DefaultModelStore holds only a sealed envelope; the approvals URL/token
	// reach the owner email change-approval admin surface (`nexus approvals`).
	DefaultModelStore          string
	DefaultModelApprovals      string
	DefaultModelApprovalsToken string
	// ReleasesDir (NEXUS_RELEASES_DIR, e.g. /data/releases) is the read-only
	// signed client release directory; empty answers 404 on /v1/releases/*
	// (docs/client-self-update.md).
	ReleasesDir string
	// MCPIssuer (NEXUS_MCP_ISSUER, e.g. https://lic.newtype-ai.com) turns on
	// the remote MCP endpoint at MCPIssuer+"/mcp" with its OAuth surface
	// (docs/nmcp-remote-endpoint.md). Empty: not served.
	MCPIssuer string
}

// ConfigFromEnv rejects implicit databases and unverified remote TLS. The local
// development exception is deliberately limited to literal loopback addresses.
// MinAdminTokenLength is the shortest accepted ADMIN_TOKEN (for example
// `openssl rand -hex 32` gives 64 characters).
const MinAdminTokenLength = 32

func ConfigFromEnv(get func(string) string) (Config, error) {
	c := Config{DSN: get("DATABASE_URL"), Schema: get("NEXUS_DB_SCHEMA"), Port: get("PORT")}
	c.DBRole = get("NEXUS_DB_ROLE")
	if c.DBRole != "" && !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(c.DBRole) {
		return Config{}, errors.New("invalid NEXUS_DB_ROLE")
	}
	for _, setting := range []struct {
		name string
		dest *int
	}{
		{"NEXUS_DB_STATEMENT_TIMEOUT_MS", &c.DBStatementTimeoutMS},
		{"NEXUS_DB_LOCK_TIMEOUT_MS", &c.DBLockTimeoutMS},
	} {
		if value := get(setting.name); value != "" {
			ms, err := strconv.ParseInt(value, 10, 32)
			if err != nil || ms <= 0 {
				return Config{}, fmt.Errorf("invalid %s", setting.name)
			}
			*setting.dest = int(ms)
		}
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.BindHost = get("NEXUS_BIND_HOST"); c.BindHost != "" {
		if ip := net.ParseIP(c.BindHost); ip == nil || !ip.IsLoopback() || ip.String() != c.BindHost {
			return Config{}, errors.New("NEXUS_BIND_HOST must be a loopback IP literal")
		}
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("invalid PORT")
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(c.Schema) || c.Schema == "public" {
		return Config{}, errors.New("NEXUS_DB_SCHEMA must name a private schema")
	}
	u, err := url.Parse(c.DSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		return Config{}, errors.New("DATABASE_URL must be a PostgreSQL URL")
	}
	query := u.Query()
	for _, key := range []string{"host", "hostaddr", "port", "service", "servicefile", "sslmode"} {
		if (key != "sslmode" && len(query[key]) != 0) || len(query[key]) > 1 {
			return Config{}, errors.New("DATABASE_URL contains connection overrides")
		}
	}
	pc, err := pgxpool.ParseConfig(c.DSN)
	if err != nil {
		return Config{}, errors.New("invalid DATABASE_URL")
	}
	local := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	dev := get("NEXUS_ALLOW_LOCAL_DB") == "1" && local
	if !dev {
		if u.Query().Get("sslmode") != "verify-full" || pc.ConnConfig.TLSConfig == nil || pc.ConnConfig.TLSConfig.InsecureSkipVerify || len(pc.ConnConfig.Fallbacks) != 0 {
			return Config{}, errors.New("DATABASE_URL requires sslmode=verify-full without fallback")
		}
		if pc.ConnConfig.Port != 5432 {
			return Config{}, errors.New("remote database requires direct/session mode port 5432")
		}
	}
	switch get("NEXUS_DB_REQUIRE_SCRAM") {
	case "":
		c.DBRequireSCRAM = !dev
	case "1":
		c.DBRequireSCRAM = true
	case "0":
		if !dev {
			// Fail closed: production may not opt out of SCRAM-only auth.
			return Config{}, errors.New("NEXUS_DB_REQUIRE_SCRAM=0 is only allowed for a local development database")
		}
	default:
		return Config{}, errors.New("NEXUS_DB_REQUIRE_SCRAM must be 0 or 1")
	}
	if get("ENROL_ALLOW") != "" || get("RESEND_API_KEY") != "" || get("MAIL_FROM") != "" || get("BASE_URL") != "" || get("ADMIN_TOKEN") != "" {
		if get("ENROL_ALLOW") == "" || get("RESEND_API_KEY") == "" || get("MAIL_FROM") == "" || get("BASE_URL") == "" {
			return Config{}, errors.New("enrolment requires BASE_URL, ENROL_ALLOW, RESEND_API_KEY and MAIL_FROM")
		}
		if admin := get("ADMIN_TOKEN"); admin != "" && len(admin) < MinAdminTokenLength {
			// Fail closed: a short operator token is guessable.
			return Config{}, fmt.Errorf("ADMIN_TOKEN must be at least %d characters when set", MinAdminTokenLength)
		}
		c.EnrolmentConfig = &gate.EnrolmentConfig{BaseURL: get("BASE_URL"), Allow: strings.Split(get("ENROL_ALLOW"), ","), AdminToken: get("ADMIN_TOKEN")}
		c.ResendAPIKey = get("RESEND_API_KEY")
		c.MailFrom = get("MAIL_FROM")
	}
	if owner := get("NEXUS_OWNER_EMAIL"); owner != "" {
		c.OwnerEmail = strings.ToLower(strings.TrimSpace(owner))
		if _, err := gate.NewOwnerCredentials(gate.NewMemoryCredentials(), c.OwnerEmail); err != nil {
			return Config{}, errors.New("NEXUS_OWNER_EMAIL must be one exact email address")
		}
		if c.EnrolmentConfig != nil {
			c.EnrolmentConfig.OwnerEmail = c.OwnerEmail
			if len(c.EnrolmentConfig.Allow) != 1 || strings.ToLower(strings.TrimSpace(c.EnrolmentConfig.Allow[0])) != c.OwnerEmail {
				return Config{}, errors.New("owner-only enrolment requires ENROL_ALLOW to equal NEXUS_OWNER_EMAIL")
			}
		}
	}
	switch get("NEXUS_OWNER_ONLY") {
	case "", "0":
	case "1":
		c.OwnerOnly = true
	default:
		return Config{}, errors.New("NEXUS_OWNER_ONLY must be 0 or 1")
	}
	if c.OwnerOnly && c.OwnerEmail == "" {
		return Config{}, errors.New("NEXUS_OWNER_ONLY requires NEXUS_OWNER_EMAIL")
	}
	if c.EnrolmentConfig != nil {
		c.EnrolmentConfig.OwnerOnly = c.OwnerOnly
	}
	switch get("NEXUS_OWNER_CODE") {
	case "", "0":
	case "1":
		if c.OwnerEmail == "" || c.EnrolmentConfig == nil {
			return Config{}, errors.New("NEXUS_OWNER_CODE requires NEXUS_OWNER_EMAIL and enrolment (BASE_URL, ENROL_ALLOW, RESEND_API_KEY, MAIL_FROM)")
		}
		c.OwnerCode = true
		c.EnrolmentConfig.OwnerCode = true
	default:
		return Config{}, errors.New("NEXUS_OWNER_CODE must be 0 or 1")
	}
	upstream, modelKey := get("MODEL_UPSTREAM"), get("MODEL_API_KEY")
	foundryEndpoint, foundryKey := get("MS_FOUNDRY_PROJECT_ENDPOINT"), get("MS_FOUNDRY_API_KEY")
	if foundryEndpoint != "" || foundryKey != "" || get("MODEL_PROTOCOL") != "" {
		if foundryEndpoint == "" || foundryKey == "" || upstream != "" || modelKey != "" {
			return Config{}, errors.New("Foundry requires endpoint and key without mixed MODEL_UPSTREAM/MODEL_API_KEY")
		}
		upstream, err = foundryModelEndpoint(foundryEndpoint, get("MODEL_PROTOCOL"))
		if err != nil {
			return Config{}, err
		}
		modelKey = foundryKey
	}
	if upstream != "" || modelKey != "" || get("MODEL_NAMES") != "" || get("MODEL_TOKEN_CEILING") != "" || get("MODEL_MAX_OUTPUT") != "" || get("MODEL_CALL_BUDGET_FILE") != "" || get("MODEL_TURN_TIMEOUT_SECONDS") != "" {
		budget, e1 := strconv.ParseInt(get("MODEL_TOKEN_CEILING"), 10, 64)
		output, e2 := strconv.ParseInt(get("MODEL_MAX_OUTPUT"), 10, 64)
		if upstream == "" || modelKey == "" || get("MODEL_NAMES") == "" || e1 != nil || e2 != nil || budget <= 0 || output <= 0 || output > budget {
			return Config{}, errors.New("model requires upstream, key, names, token ceiling and output limit")
		}
		c.ModelConfig = &gate.ModelConfig{Upstream: upstream, Key: modelKey, Models: strings.Split(get("MODEL_NAMES"), ","), Budget: budget, MaxOutput: output}
		if path := get("MODEL_CALL_BUDGET_FILE"); path != "" {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
				return Config{}, errors.New("invalid MODEL_CALL_BUDGET_FILE")
			}
			c.ModelConfig.CallBudgetFile = path
		}
		// Owner limits (decision 2026-10-04): the owner's own calls are bounded by
		// the provider (Azure), not by Newtype. Both values are optional.
		c.ModelConfig.OwnerEmail = c.OwnerEmail
		if raw := get("MODEL_OWNER_TOKEN_CEILING"); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n <= 0 || c.OwnerEmail == "" {
				return Config{}, errors.New("invalid MODEL_OWNER_TOKEN_CEILING (positive integer, requires NEXUS_OWNER_EMAIL)")
			}
			c.ModelConfig.OwnerBudget = n
		}
		if raw := get("MODEL_OWNER_MAX_OUTPUT"); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n < 0 || c.OwnerEmail == "" {
				return Config{}, errors.New("invalid MODEL_OWNER_MAX_OUTPUT (0 or positive integer, requires NEXUS_OWNER_EMAIL)")
			}
			c.ModelConfig.OwnerMaxOutput = n
		}
		if c.OwnerEmail != "" {
			ceiling := c.ModelConfig.OwnerBudget
			if ceiling == 0 {
				ceiling = gate.DefaultOwnerTokenCeiling
			}
			if c.ModelConfig.OwnerMaxOutput > ceiling {
				return Config{}, errors.New("MODEL_OWNER_MAX_OUTPUT exceeds MODEL_OWNER_TOKEN_CEILING")
			}
		}
		if raw := get("MODEL_TURN_TIMEOUT_SECONDS"); raw != "" {
			seconds, err := strconv.ParseInt(raw, 10, 32)
			if err != nil || seconds < 1 || seconds > 900 {
				return Config{}, errors.New("invalid MODEL_TURN_TIMEOUT_SECONDS")
			}
			c.ModelConfig.TurnLimit = time.Duration(seconds) * time.Second
		}
	}
	if get("SEAL_MASTER") != "" || get("DELEGATION_SIGNING_KEY") != "" || get("SIGNING_KID") != "" || get("SEAL_ISSUER") != "" {
		master, e1 := base64.StdEncoding.Strict().DecodeString(get("SEAL_MASTER"))
		seed, e2 := base64.StdEncoding.Strict().DecodeString(get("DELEGATION_SIGNING_KEY"))
		u, e3 := url.Parse(get("SEAL_ISSUER"))
		if e1 != nil || e2 != nil || len(seed) != ed25519.SeedSize || e3 != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return Config{}, errors.New("invalid sealing configuration")
		}
		deriver, e1 := seal.NewMasterDeriver(master)
		signer, e2 := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), get("SIGNING_KID"))
		if e1 != nil || e2 != nil {
			return Config{}, errors.New("invalid sealing configuration")
		}
		c.Sealer = &seal.Sealer{Signer: signer, Deriver: deriver}
		c.Issuer = get("SEAL_ISSUER")
	}
	if c.ReleasesDir = get("NEXUS_RELEASES_DIR"); c.ReleasesDir != "" && !release.ValidDir(c.ReleasesDir) {
		return Config{}, errors.New("NEXUS_RELEASES_DIR must be an absolute clean path")
	}
	if c.MCPIssuer = get("NEXUS_MCP_ISSUER"); c.MCPIssuer != "" && !validIssuer(c.MCPIssuer) {
		return Config{}, errors.New("NEXUS_MCP_ISSUER must be an https origin (or loopback http) without a path")
	}

	c.DefaultModelStore = get("MODEL_OPERATOR_STORE")
	c.DefaultModelApprovals, c.DefaultModelApprovalsToken = get("MODEL_OPERATOR_APPROVALS_URL"), get("MODEL_OPERATOR_APPROVALS_TOKEN")
	if c.DefaultModelStore != "" || c.DefaultModelApprovals != "" || c.DefaultModelApprovalsToken != "" {
		// The environment stays the bootstrap value; an operator value needs a
		// model to replace, an owner to authorize it and sealing to store it.
		if c.ModelConfig == nil || c.OwnerEmail == "" || c.Sealer == nil || c.DefaultModelStore == "" {
			return Config{}, errors.New("operator default model requires model, NEXUS_OWNER_EMAIL, sealing and MODEL_OPERATOR_STORE")
		}
		if _, err := gate.NewFileDefaultModelStore(c.DefaultModelStore); err != nil {
			return Config{}, errors.New("invalid MODEL_OPERATOR_STORE")
		}
		if (c.DefaultModelApprovals == "") != (c.DefaultModelApprovalsToken == "") {
			return Config{}, errors.New("MODEL_OPERATOR_APPROVALS_URL and MODEL_OPERATOR_APPROVALS_TOKEN must be set together")
		}
		if c.DefaultModelApprovals != "" {
			if _, err := gate.NewChangeAdminClient(c.DefaultModelApprovals, c.DefaultModelApprovalsToken, nil); err != nil {
				return Config{}, errors.New("invalid MODEL_OPERATOR_APPROVALS_URL or MODEL_OPERATOR_APPROVALS_TOKEN")
			}
		}
	}
	return c, nil
}

// validIssuer accepts an https origin, or a loopback http origin for local
// development: no path, query, fragment or userinfo.
func validIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}
