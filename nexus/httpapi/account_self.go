package httpapi

import (
	"net/http"

	"github.com/newtype-ai-com/nexus/nexus"
)

// AccountSelfVersion is the wire version of GET /v1/accounts/self.
const AccountSelfVersion = "newtype.account-self/1"

// registerAccountSelf: the authenticated person's own account id, so a person
// CLI can prove (not merely display) that a plan's account is theirs.
func (a *API) registerAccountSelf() {
	a.mux.HandleFunc("GET /v1/accounts/self", func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p.Kind != nexus.PrincipalUser {
			fail(w, nexus.ErrForbidden)
			return
		}
		write(w, 200, map[string]any{"version": AccountSelfVersion, "account": p.AccountID})
	})
}
