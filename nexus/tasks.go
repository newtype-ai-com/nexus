package nexus

import (
	"context"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

type PlanStep struct {
	ID         ids.Task `json:"id,omitempty"`
	Title      string   `json:"title"`
	Status     string   `json:"status,omitempty"`
	ActiveForm string   `json:"active_form,omitempty"`
}

func actingOn(tx Tx, actor Principal, t Task, now time.Time) error {
	if actor.Kind != PrincipalSession {
		return nil
	}
	if t.Assignee != actor.SessionID {
		return ErrForbidden
	}
	if _, err := held(tx, actor, now); err != nil {
		return err
	}
	id, err := governingDelegation(tx, actor.AccountID, t)
	if err != nil {
		return err
	}
	d, err := delegationIn(tx, actor.AccountID, id)
	if err != nil {
		return err
	}
	if d.Delegate != actor.SessionID {
		return ErrForbidden
	}
	return liveChain(tx, actor.AccountID, d, now)
}
func (s *Service) UpsertPlan(ctx context.Context, actor Principal, parent ids.Task, steps []PlanStep) ([]Task, error) {
	if len(steps) > 200 {
		return nil, ErrInvalid
	}
	var out []Task
	err := s.update(ctx, actor, func(tx Tx) error {
		out = []Task{}
		p, err := taskIn(tx, actor.AccountID, parent)
		if err != nil {
			return err
		}
		now := s.now()
		if err = actingOn(tx, actor, p, now); err != nil {
			return err
		}
		if terminalTask(p.Status) {
			return ErrConflict
		}
		kids, err := tx.TasksByParent(parent)
		if err != nil {
			return err
		}
		mine := map[ids.Task]Task{}
		for _, k := range kids {
			if k.Kind == "step" {
				mine[k.ID] = k
			}
		}
		seen := map[ids.Task]bool{}
		no := nextNo(kids)
		working := false
		for _, st := range steps {
			title, err := cleanTitle(st.Title)
			if err != nil || len(title) > 4096 {
				return ErrInvalid
			}
			status := st.Status
			if status == "" {
				status = "pending"
			}
			if status != "pending" && status != "in_progress" && status != "waiting_person" && !terminalTask(status) {
				return ErrInvalid
			}
			if seen[st.ID] && st.ID != "" {
				return ErrInvalid
			}
			t, exists := mine[st.ID]
			if !exists {
				id := st.ID
				if id == "" {
					id = ids.Task(ids.New(ids.KindTask))
				} else {
					if _, err = ids.ParseTask(string(id)); err != nil {
						return ErrInvalid
					}
					if _, err = tx.Task(id); err == nil {
						return ErrConflict
					} else if !errors.Is(err, ErrNotFound) {
						return err
					}
				}
				t = Task{ID: id, AccountID: p.AccountID, ParentID: p.ID, RootID: p.RootID, Assignee: p.Assignee, No: no, Kind: "step"}
				no++
			} else if terminalTask(t.Status) && status != t.Status {
				return ErrConflict
			}
			seen[t.ID] = true
			t.Title = title
			t.Status = status
			t.ActiveForm = ""
			if status == "in_progress" {
				working = true
				if st.ActiveForm != "" {
					t.ActiveForm, err = cleanTitle(st.ActiveForm)
					if err != nil || len(t.ActiveForm) > 4096 {
						return ErrInvalid
					}
				}
			}
			if err = tx.PutTask(t); err != nil {
				return err
			}
			if terminalTask(status) {
				if err = completeTaskTree(tx, actor.AccountID, t, now, 0, map[ids.Task]bool{}); err != nil {
					return err
				}
			}
			out = append(out, t)
		}
		for _, k := range kids {
			if k.Kind == "step" && !seen[k.ID] && !terminalTask(k.Status) {
				k.Status = "cancelled"
				k.ActiveForm = ""
				if err = tx.PutTask(k); err != nil {
					return err
				}
				if err = completeTaskTree(tx, actor.AccountID, k, now, 0, map[ids.Task]bool{}); err != nil {
					return err
				}
			}
		}
		if working && p.Status == "pending" {
			p.Status = "in_progress"
			if err = tx.PutTask(p); err != nil {
				return err
			}
		}
		_, err = hubEvent(tx, actor, p.Assignee, p.ID, "plan.updated", map[string]any{"steps": out}, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type Counts struct {
	Pending       int `json:"pending"`
	InProgress    int `json:"in_progress"`
	WaitingPerson int `json:"waiting_person"`
	Done          int `json:"done"`
	Failed        int `json:"failed"`
	Cancelled     int `json:"cancelled"`
}

func (c *Counts) add(o Counts) {
	c.Pending += o.Pending
	c.InProgress += o.InProgress
	c.WaitingPerson += o.WaitingPerson
	c.Done += o.Done
	c.Failed += o.Failed
	c.Cancelled += o.Cancelled
}
func (c *Counts) count(status string) {
	switch status {
	case "pending":
		c.Pending++
	case "in_progress":
		c.InProgress++
	case "waiting_person":
		c.WaitingPerson++
	case "done":
		c.Done++
	case "failed":
		c.Failed++
	case "cancelled":
		c.Cancelled++
	}
}

type Node struct {
	Task     Task          `json:"task"`
	Session  SessionStatus `json:"session_status"`
	Rollup   Counts        `json:"rollup"`
	Stale    bool          `json:"stale,omitempty"`
	Children []*Node       `json:"children,omitempty"`
}

func watches(tx Tx, actor Principal, t Task, now time.Time) (bool, error) {
	if actor.Kind != PrincipalSession {
		return true, nil
	}
	grants, err := held(tx, actor, now)
	if err != nil {
		return false, err
	}
	for _, d := range grants {
		if d.Task == "" && covers(d.Scope, "observe:progress") {
			return true, nil
		}
		yes, err := reaches(tx, actor.AccountID, d.Task, t.ID)
		if err != nil {
			return false, err
		}
		if yes {
			return true, nil
		}
	}
	return false, nil
}
func buildNode(tx Tx, account ids.Account, t Task, seen map[ids.Task]bool, depth int) (*Node, error) {
	if seen[t.ID] || depth >= 64 || len(seen) >= 10000 {
		return nil, ErrConflict
	}
	seen[t.ID] = true
	session, err := sessionIn(tx, account, t.Assignee)
	if err != nil {
		return nil, err
	}
	n := &Node{Task: t, Session: session.Status}
	kids, err := tx.TasksByParent(t.ID)
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if k.AccountID != account {
			return nil, ErrNotFound
		}
		child, err := buildNode(tx, account, k, seen, depth+1)
		if err != nil {
			return nil, err
		}
		n.Children = append(n.Children, child)
		n.Rollup.add(child.Rollup)
	}
	n.Stale = t.Status == "done" && (n.Rollup.Pending+n.Rollup.InProgress) > 0
	n.Rollup.count(t.Status)
	return n, nil
}
func (s *Service) Tree(ctx context.Context, actor Principal, id ids.Task) (*Node, error) {
	var out *Node
	err := s.view(ctx, actor, func(tx Tx) error {
		out = nil
		t, err := taskIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		ok, err := watches(tx, actor, t, s.now())
		if err != nil {
			return err
		}
		if !ok {
			return ErrForbidden
		}
		out, err = buildNode(tx, actor.AccountID, t, map[ids.Task]bool{}, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) Overview(ctx context.Context, actor Principal) ([]*Node, error) {
	var out []*Node
	err := s.view(ctx, actor, func(tx Tx) error {
		out = []*Node{}
		roots, err := tx.RootTasks(actor.AccountID)
		if err != nil {
			return err
		}
		for _, t := range roots {
			ok, err := watches(tx, actor, t, s.now())
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			n, err := buildNode(tx, actor.AccountID, t, map[ids.Task]bool{}, 0)
			if err != nil {
				return err
			}
			out = append(out, n)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
