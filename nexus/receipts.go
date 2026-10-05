package nexus

import (
	"context"
	"regexp"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
	"github.com/newtype-ai-com/nexus/seal"
)

// Run receipts (schema ruling §4): a public, domain-separated, signed
// statement binding a fresh consumer challenge to one live plan/3 run. Nexus
// re-checks in one transaction that the original credential still holds the
// run and the full plan authority is current. A "bootstrap" receipt is issued
// only before any release; a "dispatch" receipt only after every role was
// released (the non-consuming final dispatch check). Neither releases nor
// exports anything, and neither is a continuous lease: it states authority at
// issued_at and expires at the earliest of 10 s, the run deadline and the
// credential/delegation expiry.
//
// Version 2 (AV2-R2): each roles[] entry is the role's full public plan/3
// descriptor (secretplan.RoleDescriptor: Nexus name + generation, or the
// Keychain item, helper path/SHA256/CDHash/argv, schema and custody point,
// plus payload schema, delivery, FD and max bytes) and "released". It is
// projected from the stored, validated plan, so the consumer compares what
// the executor actually runs with its own manifest before any release.
// Version 1 (role/source/resource/fd/released only) is no longer issued.
const (
	ReceiptVersion = "newtype.run-receipt/2"
	ReceiptMaxTTL  = 10 * time.Second
)

var reChallenge = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReceiptKeys is the exact signed payload key set.
var ReceiptKeys = []string{"version", "op", "challenge", "issuer", "account", "session", "delegation", "credential_id",
	"run_id", "attempt", "plan_hash", "consumer_profile", "roles", "program", "import_policy", "cwd", "issued_at", "expires_at"}

// SecretPlanReceipt signs a receipt for op ("bootstrap" | "dispatch") and the
// consumer's challenge (64 lower-case hex).
func (s *Service) SecretPlanReceipt(ctx context.Context, actor Principal, id ids.Run, op, challenge string) (string, error) {
	if (op != "bootstrap" && op != "dispatch") || !reChallenge.MatchString(challenge) {
		return "", ErrInvalid
	}
	if s.sealer == nil || s.sealer.Signer == nil || s.issuer == "" {
		return "", ErrForbidden
	}
	var payload []byte
	err := s.view(ctx, actor, func(tx Tx) error {
		r, err := s.runFor(tx, actor, id)
		if err != nil {
			return err
		}
		c, err := s.executorIn(tx, actor, true, &r) // the original, live credential
		if err != nil {
			return err
		}
		now := s.now()
		if r.Status != "started" || !now.Before(r.Deadline) {
			return ErrConflict
		}
		p, err := secretplan.Validate([]byte(r.Plan))
		if err != nil || p.Hash != r.PlanHash || p.Version != 3 || p.Issuer != s.issuer {
			return ErrConflict
		}
		released := 0
		res := make([]string, 0, len(r.Roles))
		roles := make([]any, 0, len(r.Roles))
		if len(p.Roles) != len(r.Roles) {
			return ErrConflict
		}
		for i, x := range r.Roles {
			// the run's role rows must be the stored plan's roles, in order:
			// the signed descriptor comes from the plan, the phase from the run
			pr := p.Roles[i]
			if pr.Role != x.Role || pr.Source != x.Source || pr.Resource != x.Resource || pr.FD != x.FD {
				return ErrConflict
			}
			if x.Released {
				released++
			}
			res = append(res, x.Resource)
			d := secretplan.RoleDescriptor(pr)
			d["released"] = x.Released
			roles = append(roles, d)
		}
		if (op == "bootstrap" && released != 0) || (op == "dispatch" && released != len(r.Roles)) {
			return ErrConflict
		}
		d, err := delegationIn(tx, actor.AccountID, r.Delegation)
		if err != nil {
			return err
		}
		if err := s.planAuthority(tx, actor.AccountID, d, res); err != nil {
			return err
		}
		exp := now.Add(ReceiptMaxTTL)
		for _, t := range []time.Time{r.Deadline, c.ExpiresAt, d.ExpiresAt} {
			if t.Before(exp) {
				exp = t
			}
		}
		issued := floorSecond(now)
		exp = floorSecond(exp)
		if !exp.After(issued) {
			return ErrConflict
		}
		payload = secretplan.Encode(map[string]any{
			"version": ReceiptVersion, "op": op, "challenge": challenge, "issuer": s.issuer,
			"account": string(r.AccountID), "session": string(r.SessionID), "delegation": string(r.Delegation),
			"credential_id": r.CredentialID, "run_id": string(r.ID), "attempt": r.Attempt, "plan_hash": r.PlanHash,
			"consumer_profile": p.ConsumerProfile, "roles": roles,
			// the exact launch identity, so the consumer can bind the receipt to
			// what it is running (its own script, argv and import closure)
			"program": map[string]any{"interpreter": p.Interpreter, "script": p.Script, "args": strsAny(p.Args)},
			"import_policy": map[string]any{"interpreter": p.ImportPolicy.Interpreter, "bootstrap": p.ImportPolicy.Bootstrap,
				"stdlib_root": p.ImportPolicy.StdlibRoot, "module_roots": strsAny(p.ImportPolicy.ModuleRoots)},
			"cwd":       map[string]any{"path": p.Cwd, "directory_manifest_sha256": p.CwdManifestSHA256},
			"issued_at": issued.Unix(), "expires_at": exp.Unix(),
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	return s.sealer.Signer.SignJWS(seal.ReceiptJWSType, payload)
}

// ReceiptKeysPublic returns the receipt verification keys (the same Nexus
// signing key as delegation certificates; a consumer must install them as an
// independent trust anchor, never take them from the plan or the peer).
func (s *Service) ReceiptKeysPublic() []seal.PublicKey {
	if s.sealer == nil || s.sealer.Signer == nil {
		return nil
	}
	return s.sealer.Signer.Keys()
}

func strsAny(a []string) []any {
	out := make([]any, 0, len(a))
	for _, s := range a {
		out = append(out, s)
	}
	return out
}
