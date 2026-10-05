package nexus

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

const DefaultMonthlyTokens int64 = 10_000_000

var quotaZone = time.FixedZone("Asia/Seoul", 9*60*60)

// QuotaMonth uses the approved Korean calendar boundary, independent of host TZ.
func QuotaMonth(now time.Time) (string, time.Time) {
	local := now.In(quotaZone)
	return local.Format("2006-01"), time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, quotaZone).UTC()
}

type QuotaRequest struct {
	ID            string      `json:"request_id"`
	ClientID      string      `json:"client_event_id"`
	AccountID     ids.Account `json:"account_id"`
	Month         string      `json:"month"`
	Amount        int64       `json:"amount"`
	PreviousLimit int64       `json:"previous_limit"`
	NewLimit      int64       `json:"new_limit"`
	Status        string      `json:"status"`
	CreatedAt     time.Time   `json:"created_at"`
	ExpiresAt     time.Time   `json:"expires_at"`
	DecidedAt     time.Time   `json:"decided_at,omitempty"`
	// Private capability verifier, never serialized through an API response.
	ApprovalHash string `json:"approval_hash,omitempty"`
}

type AccountQuota struct {
	AccountID ids.Account             `json:"account_id"`
	Month     string                  `json:"month"`
	BaseLimit int64                   `json:"base_limit"`
	Increase  int64                   `json:"increase"`
	Limit     int64                   `json:"limit"`
	Used      int64                   `json:"used"`
	Remaining int64                   `json:"remaining"`
	ResetsAt  time.Time               `json:"resets_at"`
	Requests  map[string]QuotaRequest `json:"requests,omitempty"`
}

func quotaIn(tx Tx, account ids.Account, month string) (AccountQuota, error) {
	start, err := time.ParseInLocation("2006-01", month, quotaZone)
	if err != nil || ids.Check(ids.KindAccount, string(account)) != nil {
		return AccountQuota{}, ErrInvalid
	}
	q, err := tx.AccountQuota(account, month)
	if errors.Is(err, ErrNotFound) {
		_, reset := QuotaMonth(start)
		q = AccountQuota{AccountID: account, Month: month, BaseLimit: DefaultMonthlyTokens, ResetsAt: reset, Requests: map[string]QuotaRequest{}}
	} else if err != nil {
		return q, err
	}
	if q.AccountID != account || q.Month != month || q.BaseLimit < 0 || q.Increase < 0 || q.Increase > math.MaxInt64-q.BaseLimit || q.Used < 0 {
		return AccountQuota{}, ErrConflict
	}
	q.Limit = q.BaseLimit + q.Increase
	q.Remaining = max(int64(0), q.Limit-q.Used)
	if q.Requests == nil {
		q.Requests = map[string]QuotaRequest{}
	}
	return q, nil
}

func (s *Service) AccountQuota(ctx context.Context, actor Principal) (AccountQuota, error) {
	var q AccountQuota
	err := s.view(ctx, actor, func(tx Tx) error {
		if actor.Kind == PrincipalSession {
			if _, err := sessionIn(tx, actor.AccountID, actor.SessionID); err != nil {
				return err
			}
		}
		month, _ := QuotaMonth(s.now())
		var err error
		q, err = quotaIn(tx, actor.AccountID, month)
		return err
	})
	q.Requests = nil
	return q, err
}

func chargeAccountQuota(tx Tx, account ids.Account, now time.Time, tokens int64) (string, error) {
	month, _ := QuotaMonth(now)
	q, err := quotaIn(tx, account, month)
	if err != nil {
		return "", err
	}
	if tokens < 0 || tokens > q.Remaining {
		return "", ErrLimit
	}
	q.Used += tokens
	return month, tx.PutAccountQuota(q)
}
func settleAccountQuota(tx Tx, account ids.Account, month string, reserved, used int64) error {
	if month == "" {
		return nil
	} // pre-migration invocation; no retroactive charge
	q, err := quotaIn(tx, account, month)
	if err != nil {
		return err
	}
	if q.Used < reserved {
		return ErrConflict
	}
	if used < 0 {
		used = reserved
	}
	if used > math.MaxInt64-(q.Used-reserved) {
		return ErrLimit
	}
	q.Used = q.Used - reserved + used // actual overrun remains charged; it must not disappear
	return tx.PutAccountQuota(q)
}

// BeginQuotaRequest records only a proposal. Callers cannot approve it. The
// trusted Gate supplies a random private mail-capability hash, never from JSON.
func (s *Service) BeginQuotaRequest(ctx context.Context, actor Principal, id, client, hash string, amount int64) (QuotaRequest, bool, error) {
	if amount <= 0 || len(id) < 8 || len(id) > 128 || len(client) < 1 || len(client) > 128 || len(hash) != 64 {
		return QuotaRequest{}, false, ErrInvalid
	}
	var out QuotaRequest
	fresh := false
	err := s.update(ctx, actor, func(tx Tx) error {
		fresh = false
		if actor.Kind == PrincipalSession {
			if _, err := sessionIn(tx, actor.AccountID, actor.SessionID); err != nil {
				return err
			}
		}
		now := s.now()
		month, reset := QuotaMonth(now)
		// Gate IDs embed the intended month. Do not silently retarget a request
		// that crossed the reset boundary between HTTP parsing and commit.
		if len(id) > 12 && id[7:12] == "_qtr_" && id[:7] != month {
			return ErrExpired
		}
		q, err := quotaIn(tx, actor.AccountID, month)
		if err != nil {
			return err
		}
		recent := 0
		for _, r := range q.Requests {
			if r.ClientID == client {
				if r.Amount != amount {
					return ErrConflict
				}
				out = quotaRequestStatus(r, now)
				return nil
			}
			if r.CreatedAt.After(now.Add(-time.Hour)) {
				recent++
			}
		}
		if recent >= 5 || len(q.Requests) >= 1000 {
			return ErrLimit
		}
		if amount > math.MaxInt64-q.Limit {
			return ErrInvalid
		}
		expiry := now.Add(30 * time.Minute)
		if reset.Before(expiry) {
			expiry = reset
		}
		out = QuotaRequest{ID: id, ClientID: client, AccountID: actor.AccountID, Month: month, Amount: amount, PreviousLimit: q.Limit, NewLimit: q.Limit + amount, Status: "pending", CreatedAt: now.UTC(), ExpiresAt: expiry, ApprovalHash: hash}
		if _, ok := q.Requests[id]; ok {
			return ErrConflict
		}
		q.Requests[id] = out
		fresh = true
		return tx.PutAccountQuota(q)
	})
	return out, fresh, err
}
func quotaRequestStatus(r QuotaRequest, now time.Time) QuotaRequest {
	if r.Status == "pending" && !now.Before(r.ExpiresAt) {
		r.Status = "expired"
	}
	return r
}
func (s *Service) QuotaRequest(ctx context.Context, actor Principal, month, id string) (QuotaRequest, error) {
	var r QuotaRequest
	err := s.view(ctx, actor, func(tx Tx) error {
		q, err := quotaIn(tx, actor.AccountID, month)
		if err != nil {
			return err
		}
		var ok bool
		r, ok = q.Requests[id]
		if !ok {
			return ErrNotFound
		}
		r = quotaRequestStatus(r, s.now())
		return nil
	})
	return r, err
}

// DecideQuotaRequest is a trusted Gate-only boundary. The exact private mail
// capability is required even for the system principal; a chat request cannot
// stand in for approval. Decision and increase commit in the same transaction.
func (s *Service) DecideQuotaRequest(ctx context.Context, actor Principal, month, id, hash string, approve bool) (QuotaRequest, error) {
	if actor.Kind != PrincipalSystem || len(hash) != 64 {
		return QuotaRequest{}, ErrForbidden
	}
	var out QuotaRequest
	err := s.update(ctx, actor, func(tx Tx) error {
		q, err := quotaIn(tx, actor.AccountID, month)
		if err != nil {
			return err
		}
		r, ok := q.Requests[id]
		if !ok || r.ApprovalHash != hash {
			return ErrNotFound
		}
		out = quotaRequestStatus(r, s.now())
		if out.Status != "pending" {
			return ErrConflict
		}
		current, _ := QuotaMonth(s.now())
		if month != current {
			return ErrExpired
		}
		out.Status = "denied"
		if approve {
			if q.Limit != r.PreviousLimit || r.Amount <= 0 || r.Amount > math.MaxInt64-q.Limit || r.NewLimit != q.Limit+r.Amount {
				return ErrConflict
			}
			q.Increase += r.Amount
			out.Status = "applied"
		}
		out.DecidedAt = s.now().UTC()
		q.Requests[id] = out
		return tx.PutAccountQuota(q)
	})
	return out, err
}
func (s *Service) FailQuotaRequest(ctx context.Context, actor Principal, month, id string) error {
	if actor.Kind != PrincipalSystem {
		return ErrForbidden
	}
	return s.update(ctx, actor, func(tx Tx) error {
		q, err := quotaIn(tx, actor.AccountID, month)
		if err != nil {
			return err
		}
		r, ok := q.Requests[id]
		if !ok {
			return ErrNotFound
		}
		if r.Status != "pending" {
			return nil
		}
		r.Status = "failed"
		q.Requests[id] = r
		return tx.PutAccountQuota(q)
	})
}
