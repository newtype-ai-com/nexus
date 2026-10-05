package conformance

import (
	"context"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func runMessageTasks(t *testing.T, open func() nexus.Store) {
	t.Run("message_task_routing_reply_and_isolation", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b := f.issue(rootRequest()), f.issue(rootRequest())
		pa, pb := nexus.SessionPrincipal(f.account, a.Session.ID), nexus.SessionPrincipal(f.account, b.Session.ID)
		m, err := f.svc.SendTo(ctx, pa, string(b.Task.ID), nexus.Message{Text: "task addressed", Task: a.Task.ID, ClientEventID: "stable"})
		must(t, err)
		if m.To != b.Session.ID || m.SenderTask != a.Task.ID || m.About != b.Task.ID || m.AboutTitle != b.Task.Title {
			t.Fatal(m)
		}
		again, err := f.svc.SendTo(ctx, pa, "", nexus.Message{Text: "task addressed", Task: a.Task.ID, About: b.Task.ID, ClientEventID: "stable"})
		must(t, err)
		if again.Event != m.Event {
			t.Fatal("route replay duplicated message")
		}
		// The original sender's current task changes. A reply still targets the
		// original sender task, not the newer task or a payload ID substring.
		req := rootRequest()
		req.ToSessionID = a.Session.ID
		req.Title = "newer work"
		newer, err := f.svc.CreateRoot(ctx, f.person, req)
		must(t, err)
		reply, err := f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "reply", Task: b.Task.ID, ReplyTo: m.Event})
		must(t, err)
		if reply.About != a.Task.ID {
			t.Fatal("reply lost original sender task", reply)
		}
		fresh, err := f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "fresh"})
		must(t, err)
		if fresh.About != newer.Task.ID {
			t.Fatal("current task fallback wrong", fresh)
		}
		_, err = f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "spoof", Task: a.Task.ID})
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "wrong about", About: b.Task.ID})
		wantErr(t, err, nexus.ErrInvalid)
		other := newFixture(t, open)
		foreign := other.issue(rootRequest())
		_, err = f.svc.SendTo(ctx, pa, string(foreign.Task.ID), nexus.Message{Text: "cross account"})
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "cross account", About: foreign.Task.ID})
		wantErr(t, err, nexus.ErrNotFound)
		// Metadata is descriptive only and never opens raw certificate access.
		_, err = f.svc.DelegationInfo(ctx, pa, b.Delegation.ID)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("message_descendant_task_and_peer_step", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b := f.issue(rootRequest()), f.issue(rootRequest())
		pa := nexus.SessionPrincipal(f.account, a.Session.ID)
		child, err := f.svc.Delegate(ctx, f.person, nexus.DelegateRequest{Title: "delegated work", ParentID: a.Delegation.ID, ToSessionID: b.Session.ID, Scope: []string{"newtype:run"}})
		must(t, err)
		m, err := f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "about assignment", Task: a.Task.ID})
		must(t, err)
		if m.About != child.Task.ID {
			t.Fatal("sender parent did not resolve recipient child", m)
		}
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			return tx.PutTask(nexus.Task{ID: ids.Task(ids.New(ids.KindTask)), AccountID: f.account, ParentID: child.Task.ID, RootID: a.Task.ID, Assignee: b.Session.ID, Kind: "step", Title: "verify", ActiveForm: "verifying", Status: "in_progress"})
		}))
		peers, err := f.svc.Peers(ctx, pa)
		must(t, err)
		found := false
		for _, p := range peers {
			if p.SessionID == b.Session.ID {
				found = true
				if p.WorkingTaskID != child.Task.ID || p.WorkingTitle != "delegated work" || p.Step != "verifying" {
					t.Fatal(p)
				}
			}
		}
		if !found {
			t.Fatal("recipient absent")
		}
	})
}
