package nexus

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

func TestMonthlyQuotaCalendarAndApproval(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 31, 14, 59, 59, 0, time.UTC)
	st := NewMemStore()
	svc := NewService(st, func() time.Time { return now })
	actor := UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "test@example.test")
	q, err := svc.AccountQuota(ctx, actor)
	if err != nil || q.Month != "2026-10" || q.Limit != DefaultMonthlyTokens || !q.ResetsAt.Equal(now.Add(time.Second)) {
		t.Fatal(q, err)
	}
	hash := strings.Repeat("a", 64)
	r, fresh, err := svc.BeginQuotaRequest(ctx, actor, "request-1", "client-1", hash, 1234567)
	if err != nil || !fresh || r.NewLimit != 11234567 {
		t.Fatal(r, fresh, err)
	}
	if _, fresh, err := svc.BeginQuotaRequest(ctx, actor, "request-2", "client-1", hash, 1234567); err != nil || fresh {
		t.Fatal(fresh, err)
	}
	if _, _, err := svc.BeginQuotaRequest(ctx, actor, "request-3", "client-1", hash, 1); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := svc.DecideQuotaRequest(ctx, actor, r.Month, r.ID, hash, true); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := svc.DecideQuotaRequest(ctx, SystemPrincipal(actor.AccountID), r.Month, r.ID, strings.Repeat("b", 64), true); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	other := UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.test")
	if _, err := svc.QuotaRequest(ctx, other, r.Month, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	approved, err := svc.DecideQuotaRequest(ctx, SystemPrincipal(actor.AccountID), r.Month, r.ID, hash, true)
	if err != nil || approved.Status != "applied" {
		t.Fatal(approved, err)
	}
	if _, err := svc.DecideQuotaRequest(ctx, SystemPrincipal(actor.AccountID), r.Month, r.ID, hash, true); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	q, _ = svc.AccountQuota(ctx, actor)
	if q.Limit != 11234567 || q.Requests != nil {
		t.Fatal(q)
	}
	oldMonth := q.Month
	if err := st.Update(ctx, func(tx Tx) error { _, err := chargeAccountQuota(tx, actor.AccountID, now, 100); return err }); err != nil {
		t.Fatal(err)
	}
	pending, _, err := svc.BeginQuotaRequest(ctx, actor, "request-4", "client-4", hash, 99)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	q, _ = svc.AccountQuota(ctx, actor)
	if q.Month != "2026-11" || q.Used != 0 || q.Increase != 0 || q.Remaining != DefaultMonthlyTokens {
		t.Fatal(q)
	}
	if _, err := svc.DecideQuotaRequest(ctx, SystemPrincipal(actor.AccountID), pending.Month, pending.ID, hash, true); err == nil {
		t.Fatal("expired approval applied")
	}
	if err := st.Update(ctx, func(tx Tx) error { return settleAccountQuota(tx, actor.AccountID, oldMonth, 100, 7) }); err != nil {
		t.Fatal(err)
	}
	q, _ = svc.AccountQuota(ctx, actor)
	if q.Used != 0 {
		t.Fatal("previous month refund affected new month")
	}
	if err := st.View(ctx, func(tx Tx) error {
		q, err := quotaIn(tx, actor.AccountID, oldMonth)
		if q.Used != 7 || q.Increase != 1234567 {
			t.Fatal(q)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMonthlyQuotaConcurrentReservationAndOverflow(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	now := time.Now()
	account := ids.Account(ids.New(ids.KindAccount))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.Update(ctx, func(tx Tx) error { _, err := chargeAccountQuota(tx, account, now, 1_000_000); return err })
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrLimit) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 10 {
		t.Fatal(wins.Load())
	}
	svc := NewService(st, func() time.Time { return now })
	user := UserPrincipal(account, "user@example.test")
	q, _ := svc.AccountQuota(ctx, user)
	if q.Used != DefaultMonthlyTokens || q.Remaining != 0 {
		t.Fatal(q)
	}
	if _, _, err := svc.BeginQuotaRequest(ctx, user, "overflow-req", "overflow", strings.Repeat("a", 64), math.MaxInt64); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	month, _ := QuotaMonth(now)
	if err := st.Update(ctx, func(tx Tx) error { return settleAccountQuota(tx, account, month, 1_000_000, 2_000_000) }); err != nil {
		t.Fatal(err)
	}
	q, _ = svc.AccountQuota(ctx, user)
	if q.Used != 11_000_000 || q.Remaining != 0 {
		t.Fatal(q)
	}
}

func TestQuotaStaleDenialFailureAndRollback(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := NewMemStore()
	s := NewService(st, func() time.Time { return now })
	user := UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	sys := SystemPrincipal(user.AccountID)
	hash := strings.Repeat("c", 64)
	a, _, _ := s.BeginQuotaRequest(ctx, user, "request-a", "a", hash, 13)
	b, _, _ := s.BeginQuotaRequest(ctx, user, "request-b", "b", hash, 17)
	if _, err := s.DecideQuotaRequest(ctx, sys, a.Month, a.ID, hash, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideQuotaRequest(ctx, sys, b.Month, b.ID, hash, true); !errors.Is(err, ErrConflict) {
		t.Fatal("stale approved", err)
	}
	if _, err := s.DecideQuotaRequest(ctx, sys, b.Month, b.ID, hash, false); err != nil {
		t.Fatal(err)
	}
	c, _, _ := s.BeginQuotaRequest(ctx, user, "request-c", "c", hash, 19)
	if err := s.FailQuotaRequest(ctx, sys, c.Month, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideQuotaRequest(ctx, sys, c.Month, c.ID, hash, true); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	fail := errors.New("rollback")
	if err := st.Update(ctx, func(tx Tx) error {
		_, err := chargeAccountQuota(tx, user.AccountID, now, 11)
		if err != nil {
			return err
		}
		return fail
	}); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	q, _ := s.AccountQuota(ctx, user)
	if q.Limit != DefaultMonthlyTokens+13 || q.Used != 0 {
		t.Fatal(q)
	}
}
