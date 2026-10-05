package gate

import (
	"net/http"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Owner limits (decision 2026-10-04): the operator (NEXUS_OWNER_EMAIL) has no
// Newtype token or call limits; cost is capped on the provider (Azure) side.
// Defaults for the owner's own model calls:
const (
	DefaultOwnerTokenCeiling int64 = 1000000 // MODEL_OWNER_TOKEN_CEILING
	DefaultOwnerMaxOutput    int64 = 0       // MODEL_OWNER_MAX_OUTPUT: 0 = no injected cap
)

// OwnerPerson reports whether r carries the configured owner's own person
// credentials: a live licence and a live login (X-Newtype-Login), both issued
// to owner and to the same account. It is the same identity the default-model
// operator API admits (licence looked up again, never a login alone), here
// without refusing a local session header: the owner's local TUI session is
// still the owner person. Agent (nta_) and executor (nte_) bearers are never
// the owner, whatever account they belong to; seats run by the owner's own
// saved licence + login are. The decision uses only server-side credential
// records, never anything the client claims. It returns the owner's account.
func OwnerPerson(r *http.Request, store CredentialStore, owner string, now time.Time) (ids.Account, bool) {
	owner = strings.ToLower(strings.TrimSpace(owner))
	if store == nil || owner == "" {
		return "", false
	}
	if len(r.Header.Values("Authorization")) != 1 {
		return "", false
	}
	token := bearer(r)
	if token == "" || strings.HasPrefix(token, "nta_") || strings.HasPrefix(token, nexus.ExecutorTokenPrefix) {
		return "", false
	}
	logins := r.Header.Values("X-Newtype-Login")
	if len(logins) != 1 || logins[0] == "" {
		return "", false
	}
	lic, err := store.LookupCredential(r.Context(), Verifier(token))
	if err != nil || lic.Kind != "licence" || lic.Revoked || !now.Before(lic.Expires) || !SameEmail(lic.Email, owner) {
		return "", false
	}
	login, err := store.LookupCredential(r.Context(), Verifier(logins[0]))
	if err != nil || login.Kind != "login" || login.Revoked || !now.Before(login.Expires) || !SameEmail(login.Email, owner) || login.Account != lic.Account {
		return "", false
	}
	return lic.Account, true
}

// OwnerPersonFunc adapts OwnerPerson to the Nexus HTTP adapter's hook: the
// authenticated principal must be the owner's person in the owner's account.
func OwnerPersonFunc(store CredentialStore, owner string) func(*http.Request, nexus.Principal) bool {
	if strings.TrimSpace(owner) == "" {
		return nil
	}
	return func(r *http.Request, p nexus.Principal) bool {
		account, ok := OwnerPerson(r, store, owner, time.Now())
		return ok && p.Kind == nexus.PrincipalUser && p.CredentialID == "" && p.SessionID == "" && p.AccountID == account && SameEmail(p.Email, owner)
	}
}

// Owner reports the configured owner email of this owner-filtered store.
func (s *OwnerCredentials) Owner() string { return s.email }
