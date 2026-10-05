package pgstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type transaction struct {
	ctx           context.Context
	tx            pgx.Tx
	active, write bool
}

var _ nexus.Tx = (*transaction)(nil)

func (t *transaction) check(write bool) error {
	if !t.active {
		return fmt.Errorf("%w: transaction ended", nexus.ErrInvalid)
	}
	if write && !t.write {
		return fmt.Errorf("%w: write in a read-only transaction", nexus.ErrInvalid)
	}
	return t.ctx.Err()
}
func valid(kind ids.Kind, id string) bool { return ids.Check(kind, id) == nil }
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func one[T any](t *transaction, query string, args ...any) (out T, err error) {
	if err = t.check(false); err != nil {
		return
	}
	var body []byte
	err = t.tx.QueryRow(t.ctx, query, args...).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nexus.ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(body, &out)
	}
	return
}
func many[T any](t *transaction, query string, args ...any) ([]T, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	rows, err := t.tx.Query(t.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var body []byte
		var item T
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
func (t *transaction) put(query string, value any, args ...any) error {
	if err := t.check(true); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: invalid record JSON", nexus.ErrInvalid)
	}
	args = append(args, string(body))
	tag, err := t.tx.Exec(t.ctx, query, args...)
	if err == nil && tag.RowsAffected() == 0 {
		return nexus.ErrConflict
	}
	return err
}

func (t *transaction) Session(id ids.Session) (nexus.Session, error) {
	return one[nexus.Session](t, "SELECT body FROM sessions WHERE id=$1", string(id))
}
func (t *transaction) PutSession(x nexus.Session) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindSession, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO sessions(id,account_id,body) VALUES($1,$2,$3)
 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body WHERE sessions.account_id=EXCLUDED.account_id`, x, string(x.ID), string(x.AccountID))
}
func (t *transaction) SessionsByAccount(id ids.Account) ([]nexus.Session, error) {
	return many[nexus.Session](t, "SELECT body FROM sessions WHERE account_id=$1 ORDER BY id", string(id))
}
func (t *transaction) OpenSessions() ([]nexus.Session, error) {
	return many[nexus.Session](t, "SELECT body FROM sessions WHERE body->>'status' IS DISTINCT FROM 'done' ORDER BY id")
}
func (t *transaction) Task(id ids.Task) (nexus.Task, error) {
	return one[nexus.Task](t, "SELECT body FROM tasks WHERE id=$1", string(id))
}
func (t *transaction) PutTask(x nexus.Task) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindTask, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO tasks(id,account_id,parent_id,no,body) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(id) DO UPDATE SET parent_id=EXCLUDED.parent_id,no=EXCLUDED.no,body=EXCLUDED.body WHERE tasks.account_id=EXCLUDED.account_id`, x, string(x.ID), string(x.AccountID), nullable(string(x.ParentID)), x.No)
}
func (t *transaction) TasksByParent(id ids.Task) ([]nexus.Task, error) {
	return many[nexus.Task](t, "SELECT body FROM tasks WHERE parent_id=$1 ORDER BY no,id", nullable(string(id)))
}
func (t *transaction) RootTasks(id ids.Account) ([]nexus.Task, error) {
	return many[nexus.Task](t, "SELECT body FROM tasks WHERE account_id=$1 AND parent_id IS NULL ORDER BY id", string(id))
}
func (t *transaction) Delegation(id ids.Delegation) (nexus.Delegation, error) {
	return one[nexus.Delegation](t, "SELECT body FROM delegations WHERE id=$1", string(id))
}
func (t *transaction) PutDelegation(x nexus.Delegation) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindDelegation, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO delegations(id,account_id,parent_id,delegate_id,body) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(id) DO UPDATE SET parent_id=EXCLUDED.parent_id,delegate_id=EXCLUDED.delegate_id,body=EXCLUDED.body WHERE delegations.account_id=EXCLUDED.account_id`, x, string(x.ID), string(x.AccountID), nullable(string(x.ParentID)), string(x.Delegate))
}
func (t *transaction) DelegationsByParent(id ids.Delegation) ([]nexus.Delegation, error) {
	return many[nexus.Delegation](t, "SELECT body FROM delegations WHERE parent_id IS NOT DISTINCT FROM $1 ORDER BY id", nullable(string(id)))
}
func (t *transaction) DelegationsByDelegate(id ids.Session) ([]nexus.Delegation, error) {
	return many[nexus.Delegation](t, "SELECT body FROM delegations WHERE delegate_id=$1 ORDER BY id", string(id))
}
func (t *transaction) Usage(id ids.Delegation) (nexus.Usage, error) {
	out, err := one[nexus.Usage](t, "SELECT body FROM usage WHERE delegation_id=$1", string(id))
	if errors.Is(err, nexus.ErrNotFound) {
		err = nil
	}
	return out, err
}
func (t *transaction) PutUsage(id ids.Delegation, x nexus.Usage) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindDelegation, string(id)) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO usage(delegation_id,body) VALUES($1,$2) ON CONFLICT(delegation_id) DO UPDATE SET body=EXCLUDED.body`, x, string(id))
}
func (t *transaction) Policy(id ids.Policy, version int) (nexus.Policy, error) {
	return one[nexus.Policy](t, "SELECT body FROM policies WHERE id=$1 AND version=$2", string(id), version)
}
func (t *transaction) PutPolicy(x nexus.Policy) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindPolicy, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) || x.Version < 1 {
		return nexus.ErrInvalid
	}
	err := t.put(`INSERT INTO policies(id,version,account_id,body) VALUES($1,$2,$3,$4) ON CONFLICT(id,version) DO NOTHING`, x, string(x.ID), x.Version, string(x.AccountID))
	if !errors.Is(err, nexus.ErrConflict) {
		return err
	}
	old, err := t.Policy(x.ID, x.Version)
	if err != nil {
		return err
	}
	if old.AccountID != x.AccountID || old.Hash() != x.Hash() {
		return nexus.ErrConflict
	}
	return nil
}

// json.Marshal compacts RawMessage values. Insert the validated payload into
// the encoded envelope separately so whitespace, number spelling and key order
// inside the hashed payload survive the round trip through PostgreSQL json.
func marshalEvent(e nexus.Event) ([]byte, error) {
	payload := e.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	if !json.Valid(payload) {
		return nil, nexus.ErrInvalid
	}
	e.Payload = nil
	body, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return bytes.Replace(body, []byte(`"payload":null`), append([]byte(`"payload":`), payload...), 1), nil
}
func (t *transaction) AppendEvent(e nexus.Event) (nexus.Event, error) {
	if err := t.check(true); err != nil {
		return nexus.Event{}, err
	}
	if !valid(ids.KindEvent, string(e.ID)) {
		return nexus.Event{}, nexus.ErrInvalid
	}
	session, err := t.Session(e.SessionID)
	if err != nil {
		return nexus.Event{}, err
	}
	if session.AccountID != e.AccountID {
		return nexus.Event{}, nexus.ErrNotFound
	}
	var exists bool
	err = t.tx.QueryRow(t.ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id=$1 OR (session_id=$2 AND client_event_id=$3))`, string(e.ID), string(e.SessionID), nullable(e.ClientEventID)).Scan(&exists)
	if err != nil {
		return nexus.Event{}, err
	}
	if exists {
		return nexus.Event{}, nexus.ErrConflict
	}
	err = t.tx.QueryRow(t.ctx, "SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE session_id=$1", string(e.SessionID)).Scan(&e.Seq)
	if err != nil {
		return nexus.Event{}, err
	}
	err = t.tx.QueryRow(t.ctx, `INSERT INTO hub_cursors(account_id,value) VALUES($1,1) ON CONFLICT(account_id) DO UPDATE SET value=hub_cursors.value+1 RETURNING value`, string(e.AccountID)).Scan(&e.Cursor)
	if err != nil {
		return nexus.Event{}, err
	}
	body, err := marshalEvent(e)
	if err != nil {
		return nexus.Event{}, err
	}
	_, err = t.tx.Exec(t.ctx, `INSERT INTO events(account_id,cursor,id,session_id,seq,client_event_id,body) VALUES($1,$2,$3,$4,$5,$6,$7)`, string(e.AccountID), e.Cursor, string(e.ID), string(e.SessionID), e.Seq, nullable(e.ClientEventID), string(body))
	if err != nil {
		return nexus.Event{}, err
	}
	e.Payload = append([]byte(nil), e.Payload...)
	e.CausedBy = append([]ids.Event(nil), e.CausedBy...)
	return e, nil
}
func unlimited(n int) any {
	if n <= 0 {
		return nil
	}
	return n
}
func (t *transaction) Events(id ids.Session, after int64, limit int) ([]nexus.Event, error) {
	return many[nexus.Event](t, "SELECT body FROM events WHERE session_id=$1 AND seq>$2 ORDER BY seq LIMIT $3", string(id), after, unlimited(limit))
}
func (t *transaction) EventByID(session ids.Session, id ids.Event) (nexus.Event, error) {
	return one[nexus.Event](t, "SELECT body FROM events WHERE session_id=$1 AND id=$2", string(session), string(id))
}

func (t *transaction) EventByClientID(id ids.Session, cid string) (nexus.Event, error) {
	return one[nexus.Event](t, "SELECT body FROM events WHERE session_id=$1 AND client_event_id=$2", string(id), nullable(cid))
}
func (t *transaction) EventsSince(id ids.Account, after int64, limit int) ([]nexus.Event, error) {
	return many[nexus.Event](t, "SELECT body FROM events WHERE account_id=$1 AND cursor>$2 ORDER BY cursor LIMIT $3", string(id), after, unlimited(limit))
}
func (t *transaction) Cursor(id ids.Account) (int64, error) {
	if err := t.check(false); err != nil {
		return 0, err
	}
	var out int64
	err := t.tx.QueryRow(t.ctx, "SELECT value FROM hub_cursors WHERE account_id=$1", string(id)).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return out, err
}

func (t *transaction) CustodyApproval(id ids.Approval) (nexus.CustodyApproval, error) {
	return one[nexus.CustodyApproval](t, "SELECT body FROM custody_approvals WHERE id=$1", string(id))
}
func (t *transaction) PutCustodyApproval(x nexus.CustodyApproval) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindApproval, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) || !nexus.ValidCustodyHash(x.InputHash) {
		return nexus.ErrInvalid
	}
	// Same storage rule as memstore (nexus.CustodyTransitionOK), checked on the
	// locked row inside this transaction: identity is immutable, used/denied terminal.
	old, err := t.CustodyApproval(x.ID)
	switch {
	case err == nil:
		if !nexus.CustodyTransitionOK(old, x) {
			return nexus.ErrConflict
		}
	case errors.Is(err, nexus.ErrNotFound):
		if !nexus.CustodyNewOK(x) {
			return nexus.ErrConflict // a record is born pending with no decision or use
		}
	default:
		return err
	}
	return t.put(`INSERT INTO custody_approvals(id,account_id,input_hash,body) VALUES($1,$2,$3,$4)
 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body WHERE custody_approvals.account_id=EXCLUDED.account_id AND custody_approvals.input_hash=EXCLUDED.input_hash`, x, string(x.ID), string(x.AccountID), x.InputHash)
}
func (t *transaction) CustodyApprovalsByHash(account ids.Account, hash string) ([]nexus.CustodyApproval, error) {
	return many[nexus.CustodyApproval](t, "SELECT body FROM custody_approvals WHERE account_id=$1 AND input_hash=$2 ORDER BY id", string(account), hash)
}

func (t *transaction) SecretValue(account ids.Account, name string) (nexus.SecretValue, error) {
	return one[nexus.SecretValue](t, "SELECT body FROM secret_values WHERE account_id=$1 AND name=$2", string(account), name)
}
func (t *transaction) PutSecretValue(x nexus.SecretValue) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindAccount, string(x.AccountID)) || x.Name == "" || x.Version < 1 {
		return nexus.ErrInvalid
	}
	// generations never go back
	return t.put(`INSERT INTO secret_values(account_id,name,body) VALUES($1,$2,$3)
 ON CONFLICT(account_id,name) DO UPDATE SET body=EXCLUDED.body WHERE (secret_values.body->>'version')::bigint <= (EXCLUDED.body->>'version')::bigint`, x, string(x.AccountID), x.Name)
}
func (t *transaction) SecretValues(account ids.Account) ([]nexus.SecretValue, error) {
	return many[nexus.SecretValue](t, "SELECT body FROM secret_values WHERE account_id=$1 ORDER BY name", string(account))
}

func (t *transaction) ExecutorCredential(id string) (nexus.ExecutorCredential, error) {
	// Lock against a concurrent revoke only where locking is allowed: a
	// read-only transaction rejects FOR SHARE.
	if t.write {
		return one[nexus.ExecutorCredential](t, "SELECT body FROM executor_credentials WHERE id=$1 FOR SHARE", id)
	}
	return one[nexus.ExecutorCredential](t, "SELECT body FROM executor_credentials WHERE id=$1", id)
}
func (t *transaction) ExecutorCredentialByVerifier(v string) (nexus.ExecutorCredential, error) {
	return one[nexus.ExecutorCredential](t, "SELECT body FROM executor_credentials WHERE verifier=$1", v)
}
func (t *transaction) PutExecutorCredential(x nexus.ExecutorCredential) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !nexus.ExecutorCredentialOK(x) {
		return nexus.ErrInvalid
	}
	old, err := t.ExecutorCredential(x.ID)
	switch {
	case err == nil:
		if !nexus.ExecutorTransitionOK(old, x) {
			return nexus.ErrConflict
		}
	case errors.Is(err, nexus.ErrNotFound):
	default:
		return err
	}
	return t.put(`INSERT INTO executor_credentials(id,account_id,verifier,body) VALUES($1,$2,$3,$4)
 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body WHERE executor_credentials.verifier=EXCLUDED.verifier`, x, x.ID, string(x.AccountID), x.Verifier)
}
func (t *transaction) SecretPlanRun(id ids.Run) (nexus.SecretPlanRun, error) {
	return one[nexus.SecretPlanRun](t, "SELECT body FROM secret_plan_runs WHERE id=$1", string(id))
}
func (t *transaction) SecretPlanRunByAttempt(key string) (nexus.SecretPlanRun, error) {
	return one[nexus.SecretPlanRun](t, "SELECT body FROM secret_plan_runs WHERE attempt_key=$1", key)
}
func (t *transaction) PutSecretPlanRun(key string, x nexus.SecretPlanRun) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindRun, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) || key != nexus.SecretPlanAttemptKey(x) {
		return nexus.ErrInvalid // only the canonical attempt key, on insert and update
	}
	old, err := t.SecretPlanRun(x.ID)
	switch {
	case err == nil:
		if !nexus.SecretPlanRunTransitionOK(old, x) {
			return nexus.ErrConflict
		}
	case errors.Is(err, nexus.ErrNotFound):
		if !nexus.SecretPlanRunNewOK(x) {
			return nexus.ErrConflict
		}
	default:
		return err
	}
	// attempt_key is UNIQUE: a second run for the same attempt is refused by the database too.
	return t.put(`INSERT INTO secret_plan_runs(id,account_id,attempt_key,body) VALUES($1,$2,$3,$4)
 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body WHERE secret_plan_runs.attempt_key=EXCLUDED.attempt_key`, x, string(x.ID), string(x.AccountID), key)
}
