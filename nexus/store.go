package nexus

import (
	"context"
	"github.com/newtype-ai-com/nexus/ids"
)

// Store serializes atomic writes and supplies consistent read-only snapshots.
// Callbacks may be retried: callers must reset captured output on every call.
// Tx values must not escape their callback. Returned records are owned copies.
type Store interface {
	Update(context.Context, func(Tx) error) error
	View(context.Context, func(Tx) error) error
}

// Tx covers phase-one records; later phases extend it with secrets, approvals,
// passkeys and runs. Mutating methods in a View return ErrInvalid.
type Tx interface {
	AccountQuota(ids.Account, string) (AccountQuota, error)
	PutAccountQuota(AccountQuota) error
	Session(ids.Session) (Session, error)
	PutSession(Session) error
	SessionsByAccount(ids.Account) ([]Session, error)
	OpenSessions() ([]Session, error)
	Task(ids.Task) (Task, error)
	PutTask(Task) error
	TasksByParent(ids.Task) ([]Task, error)
	RootTasks(ids.Account) ([]Task, error)
	Delegation(ids.Delegation) (Delegation, error)
	PutDelegation(Delegation) error
	DelegationsByParent(ids.Delegation) ([]Delegation, error)
	DelegationsByDelegate(ids.Session) ([]Delegation, error)
	Usage(ids.Delegation) (Usage, error)
	PutUsage(ids.Delegation, Usage) error
	Policy(ids.Policy, int) (Policy, error)
	PutPolicy(Policy) error
	AppendEvent(Event) (Event, error)
	Events(ids.Session, int64, int) ([]Event, error)
	EventByID(ids.Session, ids.Event) (Event, error)
	EventByClientID(ids.Session, string) (Event, error)
	EventsSince(ids.Account, int64, int) ([]Event, error)
	Cursor(ids.Account) (int64, error)
	CustodyApproval(ids.Approval) (CustodyApproval, error)
	PutCustodyApproval(CustodyApproval) error
	CustodyApprovalsByHash(ids.Account, string) ([]CustodyApproval, error)
	SecretValue(ids.Account, string) (SecretValue, error)
	PutSecretValue(SecretValue) error
	SecretValues(ids.Account) ([]SecretValue, error)
	ExecutorCredential(string) (ExecutorCredential, error)
	ExecutorCredentialByVerifier(string) (ExecutorCredential, error)
	PutExecutorCredential(ExecutorCredential) error
	SecretPlanRun(ids.Run) (SecretPlanRun, error)
	SecretPlanRunByAttempt(string) (SecretPlanRun, error)
	PutSecretPlanRun(attemptKey string, run SecretPlanRun) error
	TeamTx
}

type accountKey struct{}

func WithAccount(ctx context.Context, account ids.Account) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}
func AccountOf(ctx context.Context) ids.Account {
	account, _ := ctx.Value(accountKey{}).(ids.Account)
	return account
}
