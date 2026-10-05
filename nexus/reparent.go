package nexus

import (
	"context"
	"reflect"
	"sort"

	"github.com/newtype-ai-com/nexus/ids"
)

type ReparentResult struct {
	Task     Task                              `json:"task"`
	Narrowed []string                          `json:"narrowed"`
	Reissued map[ids.Delegation]ids.Delegation `json:"reissued"`
}

func intersectScopes(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		for _, y := range b {
			if covers([]string{x}, y) {
				set[y] = true
			}
			if covers([]string{y}, x) {
				set[x] = true
			}
		}
	}
	out := []string{}
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// frozenPolicy retains all restrictions from the old chain. Moving a task must
// not silently discard an ancestor's deny/ask, even when the new parent allows it.
func frozenPolicy(tx Tx, account ids.Account, d Delegation) (Policy, error) {
	var policies []Policy
	actions := map[string]bool{}
	seen := map[ids.Delegation]bool{}
	approver := "parent"
	for {
		if seen[d.ID] || len(seen) >= 64 {
			return Policy{}, ErrConflict
		}
		seen[d.ID] = true
		p, err := tx.Policy(d.Policy.ID, d.Policy.Version)
		if err != nil {
			return Policy{}, err
		}
		if p.AccountID != account || p.Hash() != d.Policy.Hash {
			return Policy{}, ErrConflict
		}
		policies = append(policies, p)
		if p.Approver == "user" {
			approver = "user"
		}
		for _, r := range p.Rules {
			actions[r.Action] = true
		}
		if d.ParentID == "" {
			break
		}
		d, err = delegationIn(tx, account, d.ParentID)
		if err != nil {
			return Policy{}, err
		}
	}
	rules := []Rule{}
	for action := range actions {
		effect := ""
		for _, p := range policies {
			e, ok := p.decide(action)
			if ok && (effect == "" || e == "deny" || (e == "ask" && effect == "auto")) {
				effect = e
			}
		}
		if effect != "" {
			rules = append(rules, Rule{action, effect})
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Action < rules[j].Action })
	return makePolicy(account, rules, approver)
}

// Reparent atomically settles the old tree, then reissues its live mandates.
// No live grant is edited in place. A narrowing without explicit acceptance
// rolls back the entire transaction, including old usage and ledger events.
func (s *Service) Reparent(ctx context.Context, actor Principal, id, newParent ids.Task, accept bool) (ReparentResult, error) {
	if actor.Kind != PrincipalUser {
		return ReparentResult{}, ErrForbidden
	}
	var out ReparentResult
	err := s.update(ctx, actor, func(tx Tx) error {
		out = ReparentResult{Narrowed: []string{}, Reissued: map[ids.Delegation]ids.Delegation{}}
		top, err := taskIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if top.Kind != "request" && top.Kind != "delegated" {
			return ErrInvalid
		}
		if terminalTask(top.Status) {
			return ErrConflict
		}
		if top.ParentID == newParent {
			return ErrInvalid
		}
		now := s.now().UTC()
		old, err := delegationIn(tx, actor.AccountID, top.DelegationID)
		if err != nil {
			return err
		}
		if err = liveChain(tx, actor.AccountID, old, now); err != nil {
			return err
		}
		var parent Task
		var gov Delegation
		if newParent != "" {
			parent, err = taskIn(tx, actor.AccountID, newParent)
			if err != nil {
				return err
			}
			if terminalTask(parent.Status) {
				return ErrConflict
			}
			cycle, err := reaches(tx, actor.AccountID, top.ID, newParent)
			if err != nil {
				return err
			}
			if cycle || parent.Assignee == top.Assignee {
				return ErrInvalid
			}
			gid, err := governingDelegation(tx, actor.AccountID, parent)
			if err != nil {
				return err
			}
			gov, err = delegationIn(tx, actor.AccountID, gid)
			if err != nil {
				return err
			}
			if err = liveChain(tx, actor.AccountID, gov, now); err != nil {
				return err
			}
			if _, err = held(tx, SessionPrincipal(actor.AccountID, gov.Delegate), now); err != nil {
				return err
			}
			if !covers(gov.Scope, "session:delegate") {
				return ErrForbidden
			}
			if gov.Limits.MaxDepth < 1 || gov.Depth >= DefaultMaxDepth {
				return ErrLimit
			}
			if err = sweepExpired(tx, actor.AccountID, gov.ID, now); err != nil {
				return err
			}
		}
		// Snapshot tasks and live grants before wind-down changes task/session states.
		var tasks []Task
		seenTasks := map[ids.Task]bool{}
		var walkTasks func(Task, int) error
		walkTasks = func(t Task, depth int) error {
			if depth >= 64 || seenTasks[t.ID] || len(tasks) >= 10000 {
				return ErrConflict
			}
			seenTasks[t.ID] = true
			tasks = append(tasks, t)
			kids, err := tx.TasksByParent(t.ID)
			if err != nil {
				return err
			}
			for _, k := range kids {
				if k.AccountID != actor.AccountID {
					return ErrNotFound
				}
				if err = walkTasks(k, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err = walkTasks(top, 0); err != nil {
			return err
		}
		var grants []Delegation
		policies := map[ids.Delegation]Policy{}
		sessions := map[ids.Session]Session{}
		seen := map[ids.Delegation]bool{}
		var walkGrants func(Delegation, int) error
		walkGrants = func(d Delegation, depth int) error {
			if depth >= 64 || seen[d.ID] {
				return ErrConflict
			}
			seen[d.ID] = true
			if err := liveChain(tx, actor.AccountID, d, now); err != nil {
				return err
			}
			if !seenTasks[d.Task] {
				return ErrConflict
			}
			grants = append(grants, d)
			p, err := frozenPolicy(tx, actor.AccountID, d)
			if err != nil {
				return err
			}
			policies[d.ID] = p
			session, err := sessionIn(tx, actor.AccountID, d.Delegate)
			if err != nil {
				return err
			}
			sessions[d.Delegate] = session
			kids, err := tx.DelegationsByParent(d.ID)
			if err != nil {
				return err
			}
			for _, k := range kids {
				if k.EndedAt != nil {
					continue
				}
				if !now.Before(k.ExpiresAt) {
					if _, err = endDelegation(tx, actor.AccountID, k.ID, "expired", now); err != nil {
						return err
					}
					continue
				}
				if err = walkGrants(k, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err = walkGrants(old, 0); err != nil {
			return err
		}
		if _, err = endDelegation(tx, actor.AccountID, old.ID, "superseded", now); err != nil {
			return err
		}
		newGrants := map[ids.Delegation]Delegation{}
		for _, d := range grants {
			usage, err := tx.Usage(d.ID)
			if err != nil {
				return err
			}
			limits, err := subLimits(d.Limits, usage.Consumed)
			if err != nil {
				return err
			}
			n := d
			n.ID = ids.Delegation(ids.New(ids.KindDelegation))
			n.ParentID = ""
			n.RootID = n.ID
			n.Depth = 0
			n.Delegator = actor
			n.IssuedAt = now
			n.EndedAt = nil
			n.EndReason = ""
			n.SupersededBy = ""
			n.Limits = limits
			n.Scope = append([]string{}, d.Scope...)
			n.Policy = policyRef(policies[d.ID])
			var above Delegation
			hasParent := false
			if d.ID == old.ID {
				above = gov
				hasParent = newParent != ""
			} else {
				var ok bool
				above, ok = newGrants[d.ParentID]
				if !ok {
					return ErrConflict
				}
				hasParent = true
			}
			if hasParent {
				if !covers(above.Scope, "session:delegate") || above.Limits.MaxDepth < 1 || above.Depth >= DefaultMaxDepth {
					return ErrLimit
				}
				pu, err := tx.Usage(above.ID)
				if err != nil {
					return err
				}
				left, err := remaining(above.Limits, pu)
				if err != nil {
					return err
				}
				n.ParentID = above.ID
				n.RootID = above.RootID
				n.Depth = above.Depth + 1
				n.Principal = above.Principal
				n.Scope = intersectScopes(n.Scope, above.Scope)
				n.Limits.ModelTokens = min(n.Limits.ModelTokens, left.ModelTokens)
				n.Limits.RuntimeMinutes = min(n.Limits.RuntimeMinutes, left.RuntimeMinutes)
				n.Limits.SubSessions = min(n.Limits.SubSessions, left.SubSessions)
				n.Limits.Spend = min(n.Limits.Spend, left.Spend)
				n.Limits.MaxDepth = min(n.Limits.MaxDepth, above.Limits.MaxDepth-1)
				if n.Limits.Currency != above.Limits.Currency {
					n.Limits.Spend = 0
				}
				if above.ExpiresAt.Before(n.ExpiresAt) {
					n.ExpiresAt = above.ExpiresAt
				}
				pu.Reserved, err = addLimits(pu.Reserved, n.Limits)
				if err != nil {
					return err
				}
				if err = tx.PutUsage(above.ID, pu); err != nil {
					return err
				}
			}
			if !reflect.DeepEqual(n.Scope, d.Scope) {
				out.Narrowed = append(out.Narrowed, string(d.ID)+":scope")
			}
			if n.Limits != limits {
				out.Narrowed = append(out.Narrowed, string(d.ID)+":limits")
			}
			if n.ExpiresAt.Before(d.ExpiresAt) {
				out.Narrowed = append(out.Narrowed, string(d.ID)+":expiry")
			}
			if len(out.Narrowed) > 0 && !accept {
				return ErrConflict
			}
			if err = tx.PutPolicy(policies[d.ID]); err != nil {
				return err
			}
			if err = tx.PutDelegation(n); err != nil {
				return err
			}
			if err = tx.PutUsage(n.ID, Usage{}); err != nil {
				return err
			}
			ended, err := delegationIn(tx, actor.AccountID, d.ID)
			if err != nil {
				return err
			}
			ended.SupersededBy = n.ID
			if err = tx.PutDelegation(ended); err != nil {
				return err
			}
			newGrants[d.ID] = n
			out.Reissued[d.ID] = n.ID
			if _, err = hubEvent(tx, actor, n.Delegate, n.Task, "delegation.reissued", map[string]any{"old": d.ID, "new": issuanceSummary(n)}, now); err != nil {
				return err
			}
		}
		top.ParentID = newParent
		top.Kind = "request"
		top.RootID = top.ID
		var siblings []Task
		if newParent != "" {
			top.Kind = "delegated"
			top.RootID = parent.RootID
			siblings, err = tx.TasksByParent(newParent)
		} else {
			siblings, err = tx.RootTasks(actor.AccountID)
		}
		if err != nil {
			return err
		}
		top.No = nextNo(siblings)
		for _, t := range tasks {
			if t.ID == top.ID {
				t = top
			}
			t.RootID = top.RootID
			if replacement, ok := out.Reissued[t.DelegationID]; ok {
				t.DelegationID = replacement
			} else if t.DelegationID != "" {
				current, err := taskIn(tx, actor.AccountID, t.ID)
				if err != nil {
					return err
				}
				t.Status = current.Status
			}
			if err = tx.PutTask(t); err != nil {
				return err
			}
			if t.ID == top.ID {
				out.Task = t
			}
		}
		for _, session := range sessions {
			if err = tx.PutSession(session); err != nil {
				return err
			}
		}
		recipients := map[ids.Session]bool{top.Assignee: true}
		if top.ParentID != "" {
			recipients[parent.Assignee] = true
		}
		if tasks[0].ParentID != "" {
			p, err := taskIn(tx, actor.AccountID, tasks[0].ParentID)
			if err != nil {
				return err
			}
			recipients[p.Assignee] = true
		}
		for sid := range recipients {
			if _, err = hubEvent(tx, actor, sid, top.ID, "task.reparented", map[string]any{"task_id": top.ID, "from": tasks[0].ParentID, "to": newParent, "narrowed": out.Narrowed}, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ReparentResult{}, err
	}
	return out, nil
}
