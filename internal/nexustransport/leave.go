package nexustransport

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// LeaveTimeout bounds the one request Leave makes. The process is ending; it
// must not hang on a slow server, and it must not skip the report either.
const LeaveTimeout = 5 * time.Second

// leaveTimeout is what Leave actually waits; tests shorten it to prove that a
// server which never answers cannot hold the exiting process.
var leaveTimeout = LeaveTimeout

// Leave tells Nexus that the session this process worked as has lost its
// runner: the TUI is ending, or restarting into a new binary.
//
// Left unsaid, Nexus finds out only by presence timeout, and until then the
// session shows as waiting: peers write to it and wait for a reader that is
// gone. A session that says it stopped is refused by name at once, and comes
// back — same id, same ledger, same inbox — when a process works as it again
// and reports running.
//
// Only the session named in auth is touched, and only when auth is a person's
// local identity (licence + login + session). An agent-token identity
// (nta_…, a container's own run) reports its own end through its run and
// is not stopped from here. Nothing else is reported: no authority, no
// approvals, no delegations change hands.
//
// Leave never reuses the caller's context: at shutdown that context is
// usually already cancelled. It gets its own short deadline.
func Leave(endpoint string, auth Auth) error {
	if auth.Login == "" || auth.Session == "" {
		return nil
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := ids.Check(ids.KindSession, auth.Session); err != nil {
		return errors.New("invalid Nexus session to leave")
	}
	client, err := New(endpoint, Auth{Token: auth.Token, Login: auth.Login, Session: auth.Session})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), leaveTimeout)
	defer cancel()
	// A session may set its own status to stopped (nexus.SetSessionStatus);
	// StoppedBy records that the session itself said so, so presence sweeps
	// never undo it and only an explicit report of running brings it back.
	return client.Do(ctx, "POST", "/v1/sessions/"+url.PathEscape(auth.Session)+"/status",
		map[string]any{"status": nexus.SessionStopped}, nil)
}
