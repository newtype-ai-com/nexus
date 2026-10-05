package nexus

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/newtype-ai-com/nexus/ids"
)

type policyKey struct {
	id      ids.Policy
	version int
}
type memData struct {
	quotas      map[string]AccountQuota
	sessions    map[ids.Session]Session
	tasks       map[ids.Task]Task
	delegations map[ids.Delegation]Delegation
	policies    map[policyKey]Policy
	usage       map[ids.Delegation]Usage
	events      map[ids.Session][]Event
	cursors     map[ids.Account]int64
	custody     map[ids.Approval]CustodyApproval
	secrets     map[secretKeyOf]SecretValue
	executors   map[string]ExecutorCredential
	runs        map[ids.Run]SecretPlanRun
	runKeys     map[string]ids.Run
	teams       *teamData
}

type secretKeyOf struct {
	account ids.Account
	name    string
}

func newMemData() *memData {
	return &memData{
		quotas:   map[string]AccountQuota{},
		sessions: map[ids.Session]Session{}, tasks: map[ids.Task]Task{},
		delegations: map[ids.Delegation]Delegation{}, policies: map[policyKey]Policy{},
		usage: map[ids.Delegation]Usage{}, events: map[ids.Session][]Event{}, cursors: map[ids.Account]int64{},
		custody: map[ids.Approval]CustodyApproval{}, secrets: map[secretKeyOf]SecretValue{},
		executors: map[string]ExecutorCredential{}, runs: map[ids.Run]SecretPlanRun{}, runKeys: map[string]ids.Run{},
		teams: newTeamData(),
	}
}
func cloneDelegation(d Delegation) Delegation {
	d.Scope = append([]string(nil), d.Scope...)
	if d.EndedAt != nil {
		at := *d.EndedAt
		d.EndedAt = &at
	}
	return d
}
func clonePolicy(p Policy) Policy { p.Rules = append([]Rule(nil), p.Rules...); return p }
func cloneEvent(e Event) Event {
	e.Payload = append([]byte(nil), e.Payload...)
	e.CausedBy = append([]ids.Event(nil), e.CausedBy...)
	return e
}

// MemStore is intended for tests and local use. Each write stages a private
// snapshot and swaps it only on success. Copy-on-write events avoid aliasing
// base slices. Postgres will implement the same Store contract independently.
type MemStore struct {
	mu   sync.RWMutex
	data *memData
}

func NewMemStore() *MemStore { return &MemStore{data: newMemData()} }
func copyData(base *memData) *memData {
	next := newMemData()
	for k, v := range base.quotas {
		next.quotas[k] = cloneQuota(v)
	}
	for k, v := range base.sessions {
		next.sessions[k] = v
	}
	for k, v := range base.tasks {
		next.tasks[k] = v
	}
	for k, v := range base.delegations {
		next.delegations[k] = v
	}
	for k, v := range base.policies {
		next.policies[k] = v
	}
	for k, v := range base.usage {
		next.usage[k] = v
	}
	for k, v := range base.events {
		next.events[k] = v
	}
	for k, v := range base.cursors {
		next.cursors[k] = v
	}
	for k, v := range base.custody {
		next.custody[k] = v
	}
	for k, v := range base.secrets {
		next.secrets[k] = v
	}
	for k, v := range base.executors {
		next.executors[k] = v
	}
	for k, v := range base.runs {
		next.runs[k] = v
	}
	for k, v := range base.runKeys {
		next.runKeys[k] = v
	}
	next.teams = base.teams.clone()
	return next
}
func (m *MemStore) Update(ctx context.Context, fn func(Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.data == nil {
		m.data = newMemData()
	}
	tx := &memTx{data: copyData(m.data), active: true, write: true}
	defer func() { tx.active = false }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.data = tx.data
	return nil
}
func (m *MemStore) View(ctx context.Context, fn func(Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	data := m.data
	if data == nil {
		data = newMemData()
	}
	tx := &memTx{data: data, active: true}
	defer func() { tx.active = false }()
	if err := fn(tx); err != nil {
		return err
	}
	return ctx.Err()
}

type memTx struct {
	data          *memData
	active, write bool
}

func (t *memTx) check(write bool) error {
	if !t.active {
		return fmt.Errorf("%w: transaction ended", ErrInvalid)
	}
	if write && !t.write {
		return fmt.Errorf("%w: write in a read-only transaction", ErrInvalid)
	}
	return nil
}
func valid(k ids.Kind, s string) error {
	if ids.Check(k, s) != nil {
		return ErrInvalid
	}
	return nil
}
func (t *memTx) Session(id ids.Session) (Session, error) {
	if err := t.check(false); err != nil {
		return Session{}, err
	}
	s, ok := t.data.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}
func (t *memTx) PutSession(s Session) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindSession, string(s.ID)) != nil || valid(ids.KindAccount, string(s.AccountID)) != nil {
		return ErrInvalid
	}
	if old, ok := t.data.sessions[s.ID]; ok && old.AccountID != s.AccountID {
		return ErrConflict
	}
	t.data.sessions[s.ID] = s
	return nil
}
func (t *memTx) SessionsByAccount(account ids.Account) ([]Session, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Session{}
	for _, s := range t.data.sessions {
		if s.AccountID == account {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) OpenSessions() ([]Session, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Session{}
	for _, s := range t.data.sessions {
		if s.Status != SessionDone {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) Task(id ids.Task) (Task, error) {
	if err := t.check(false); err != nil {
		return Task{}, err
	}
	x, ok := t.data.tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	return x, nil
}
func (t *memTx) PutTask(x Task) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindTask, string(x.ID)) != nil || valid(ids.KindAccount, string(x.AccountID)) != nil {
		return ErrInvalid
	}
	if old, ok := t.data.tasks[x.ID]; ok && old.AccountID != x.AccountID {
		return ErrConflict
	}
	t.data.tasks[x.ID] = x
	return nil
}
func (t *memTx) TasksByParent(parent ids.Task) ([]Task, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Task{}
	if parent != "" {
		for _, x := range t.data.tasks {
			if x.ParentID == parent {
				out = append(out, x)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].No != out[j].No {
			return out[i].No < out[j].No
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
func (t *memTx) RootTasks(account ids.Account) ([]Task, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Task{}
	for _, x := range t.data.tasks {
		if x.AccountID == account && x.ParentID == "" {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) Delegation(id ids.Delegation) (Delegation, error) {
	if err := t.check(false); err != nil {
		return Delegation{}, err
	}
	x, ok := t.data.delegations[id]
	if !ok {
		return Delegation{}, ErrNotFound
	}
	return cloneDelegation(x), nil
}
func (t *memTx) PutDelegation(x Delegation) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindDelegation, string(x.ID)) != nil || valid(ids.KindAccount, string(x.AccountID)) != nil {
		return ErrInvalid
	}
	if old, ok := t.data.delegations[x.ID]; ok && old.AccountID != x.AccountID {
		return ErrConflict
	}
	t.data.delegations[x.ID] = cloneDelegation(x)
	return nil
}
func (t *memTx) delegations(match func(Delegation) bool) ([]Delegation, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Delegation{}
	for _, x := range t.data.delegations {
		if match(x) {
			out = append(out, cloneDelegation(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) DelegationsByParent(id ids.Delegation) ([]Delegation, error) {
	return t.delegations(func(d Delegation) bool { return d.ParentID == id })
}
func (t *memTx) DelegationsByDelegate(id ids.Session) ([]Delegation, error) {
	return t.delegations(func(d Delegation) bool { return d.Delegate == id })
}
func (t *memTx) Usage(id ids.Delegation) (Usage, error) {
	if err := t.check(false); err != nil {
		return Usage{}, err
	}
	return t.data.usage[id], nil
}
func (t *memTx) PutUsage(id ids.Delegation, u Usage) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindDelegation, string(id)) != nil {
		return ErrInvalid
	}
	t.data.usage[id] = u
	return nil
}
func (t *memTx) Policy(id ids.Policy, version int) (Policy, error) {
	if err := t.check(false); err != nil {
		return Policy{}, err
	}
	x, ok := t.data.policies[policyKey{id, version}]
	if !ok {
		return Policy{}, ErrNotFound
	}
	return clonePolicy(x), nil
}
func (t *memTx) PutPolicy(p Policy) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindPolicy, string(p.ID)) != nil || valid(ids.KindAccount, string(p.AccountID)) != nil || p.Version < 1 {
		return ErrInvalid
	}
	k := policyKey{p.ID, p.Version}
	if old, ok := t.data.policies[k]; ok {
		if old.AccountID == p.AccountID && old.Hash() == p.Hash() {
			return nil
		}
		return ErrConflict
	}
	t.data.policies[k] = clonePolicy(p)
	return nil
}
func (t *memTx) AppendEvent(e Event) (Event, error) {
	if err := t.check(true); err != nil {
		return Event{}, err
	}
	if valid(ids.KindEvent, string(e.ID)) != nil {
		return Event{}, ErrInvalid
	}
	session, err := t.Session(e.SessionID)
	if err != nil {
		return Event{}, err
	}
	if session.AccountID != e.AccountID {
		return Event{}, ErrNotFound
	}
	for _, events := range t.data.events {
		for _, old := range events {
			if old.ID == e.ID || (old.SessionID == e.SessionID && e.ClientEventID != "" && old.ClientEventID == e.ClientEventID) {
				return Event{}, ErrConflict
			}
		}
	}
	events := t.data.events[e.SessionID]
	e.Seq = int64(len(events)) + 1
	e.Cursor = t.data.cursors[e.AccountID] + 1
	t.data.cursors[e.AccountID] = e.Cursor
	next := make([]Event, len(events)+1)
	copy(next, events)
	next[len(events)] = cloneEvent(e)
	t.data.events[e.SessionID] = next
	return cloneEvent(e), nil
}
func (t *memTx) Events(id ids.Session, after int64, limit int) ([]Event, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Event{}
	for _, e := range t.data.events[id] {
		if e.Seq > after {
			out = append(out, cloneEvent(e))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (t *memTx) EventByID(session ids.Session, id ids.Event) (Event, error) {
	if err := t.check(false); err != nil {
		return Event{}, err
	}
	for _, e := range t.data.events[session] {
		if e.ID == id {
			return cloneEvent(e), nil
		}
	}
	return Event{}, ErrNotFound
}

func (t *memTx) EventByClientID(id ids.Session, cid string) (Event, error) {
	if err := t.check(false); err != nil {
		return Event{}, err
	}
	if cid != "" {
		for _, e := range t.data.events[id] {
			if e.ClientEventID == cid {
				return cloneEvent(e), nil
			}
		}
	}
	return Event{}, ErrNotFound
}
func (t *memTx) EventsSince(account ids.Account, after int64, limit int) ([]Event, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Event{}
	for _, events := range t.data.events {
		for _, e := range events {
			if e.AccountID == account && e.Cursor > after {
				out = append(out, cloneEvent(e))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cursor < out[j].Cursor })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (t *memTx) Cursor(account ids.Account) (int64, error) {
	if err := t.check(false); err != nil {
		return 0, err
	}
	return t.data.cursors[account], nil
}

func cloneCustody(x CustodyApproval) CustodyApproval {
	if x.DecidedAt != nil {
		at := *x.DecidedAt
		x.DecidedAt = &at
	}
	if x.UsedAt != nil {
		at := *x.UsedAt
		x.UsedAt = &at
	}
	return x
}
func (t *memTx) CustodyApproval(id ids.Approval) (CustodyApproval, error) {
	if err := t.check(false); err != nil {
		return CustodyApproval{}, err
	}
	x, ok := t.data.custody[id]
	if !ok {
		return CustodyApproval{}, ErrNotFound
	}
	return cloneCustody(x), nil
}
func (t *memTx) PutCustodyApproval(x CustodyApproval) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindApproval, string(x.ID)) != nil || valid(ids.KindAccount, string(x.AccountID)) != nil || !validCustodyHash(x.InputHash) {
		return ErrInvalid
	}
	if old, ok := t.data.custody[x.ID]; ok && !CustodyTransitionOK(old, x) {
		return ErrConflict
	} else if !ok && (x.Status != "pending" || !custodyConsistentNew(x)) {
		return ErrConflict // a record is born pending with no decision or use
	}
	t.data.custody[x.ID] = cloneCustody(x)
	return nil
}
func (t *memTx) CustodyApprovalsByHash(account ids.Account, hash string) ([]CustodyApproval, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []CustodyApproval{}
	for _, x := range t.data.custody {
		if x.AccountID == account && x.InputHash == hash {
			out = append(out, cloneCustody(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func cloneSecret(x SecretValue) SecretValue {
	x.Ciphertext = append([]byte(nil), x.Ciphertext...)
	if x.UsedAt != nil {
		at := *x.UsedAt
		x.UsedAt = &at
	}
	return x
}
func (t *memTx) SecretValue(account ids.Account, name string) (SecretValue, error) {
	if err := t.check(false); err != nil {
		return SecretValue{}, err
	}
	x, ok := t.data.secrets[secretKeyOf{account, name}]
	if !ok {
		return SecretValue{}, ErrNotFound
	}
	return cloneSecret(x), nil
}
func (t *memTx) PutSecretValue(x SecretValue) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindAccount, string(x.AccountID)) != nil || !secretName.MatchString(x.Name) || x.Version < 1 {
		return ErrInvalid
	}
	if old, ok := t.data.secrets[secretKeyOf{x.AccountID, x.Name}]; ok && x.Version < old.Version {
		return ErrConflict // generations never go back
	}
	t.data.secrets[secretKeyOf{x.AccountID, x.Name}] = cloneSecret(x)
	return nil
}
func (t *memTx) SecretValues(account ids.Account) ([]SecretValue, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []SecretValue{}
	for k, x := range t.data.secrets {
		if k.account == account {
			out = append(out, cloneSecret(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func cloneExecutor(x ExecutorCredential) ExecutorCredential {
	if x.RevokedAt != nil {
		at := *x.RevokedAt
		x.RevokedAt = &at
	}
	return x
}
func (t *memTx) ExecutorCredential(id string) (ExecutorCredential, error) {
	if err := t.check(false); err != nil {
		return ExecutorCredential{}, err
	}
	x, ok := t.data.executors[id]
	if !ok {
		return ExecutorCredential{}, ErrNotFound
	}
	return cloneExecutor(x), nil
}
func (t *memTx) ExecutorCredentialByVerifier(v string) (ExecutorCredential, error) {
	if err := t.check(false); err != nil {
		return ExecutorCredential{}, err
	}
	for _, x := range t.data.executors {
		if x.Verifier == v {
			return cloneExecutor(x), nil
		}
	}
	return ExecutorCredential{}, ErrNotFound
}
func (t *memTx) PutExecutorCredential(x ExecutorCredential) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !ExecutorCredentialOK(x) {
		return ErrInvalid
	}
	if old, ok := t.data.executors[x.ID]; ok && !ExecutorTransitionOK(old, x) {
		return ErrConflict
	}
	for id, other := range t.data.executors {
		if id != x.ID && other.Verifier == x.Verifier {
			return ErrConflict
		}
	}
	t.data.executors[x.ID] = cloneExecutor(x)
	return nil
}
func cloneRun(x SecretPlanRun) SecretPlanRun {
	roles := make([]SecretPlanRole, len(x.Roles))
	for i, r := range x.Roles {
		if r.AuthorisedUntil != nil {
			at := *r.AuthorisedUntil
			r.AuthorisedUntil = &at
		}
		roles[i] = r
	}
	x.Roles = roles
	if x.FinishedAt != nil {
		at := *x.FinishedAt
		x.FinishedAt = &at
	}
	return x
}
func (t *memTx) SecretPlanRun(id ids.Run) (SecretPlanRun, error) {
	if err := t.check(false); err != nil {
		return SecretPlanRun{}, err
	}
	x, ok := t.data.runs[id]
	if !ok {
		return SecretPlanRun{}, ErrNotFound
	}
	return cloneRun(x), nil
}
func (t *memTx) SecretPlanRunByAttempt(key string) (SecretPlanRun, error) {
	if err := t.check(false); err != nil {
		return SecretPlanRun{}, err
	}
	id, ok := t.data.runKeys[key]
	if !ok {
		return SecretPlanRun{}, ErrNotFound
	}
	return cloneRun(t.data.runs[id]), nil
}
func (t *memTx) PutSecretPlanRun(key string, x SecretPlanRun) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindRun, string(x.ID)) != nil || valid(ids.KindAccount, string(x.AccountID)) != nil || key != SecretPlanAttemptKey(x) {
		return ErrInvalid // only the canonical attempt key, on insert and update
	}
	if id, ok := t.data.runKeys[key]; ok && id != x.ID {
		return ErrConflict // the attempt key is unique forever
	}
	if _, exists := t.data.runs[x.ID]; exists {
		if id, ok := t.data.runKeys[key]; !ok || id != x.ID {
			return ErrConflict // an existing run keeps its one attempt key (no alias)
		}
	}
	if old, ok := t.data.runs[x.ID]; ok && !SecretPlanRunTransitionOK(old, x) {
		return ErrConflict
	} else if !ok && !SecretPlanRunNewOK(x) {
		return ErrConflict
	}
	t.data.runs[x.ID] = cloneRun(x)
	t.data.runKeys[key] = x.ID
	return nil
}
