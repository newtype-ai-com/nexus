package core

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// M21 — how callModel decides to call again after a failed model request.
//
// Before: three attempts, 2s then 4s, for anything not classified permanent,
// including HTTP 429. Under a rate limit that is the worst possible shape:
// it adds requests to a window that is already refusing them, and when the
// Gate has itself waited up to 90 seconds it multiplies that wait by the
// client's own ladder.
//
// Now: a rate-limit refusal relayed by an authenticated Gate that has already
// spent its retry budget (GateRetryExhausted) is final for this turn — no
// client retry. A direct provider 429 (no Gate) is retried only within a small
// bounded budget, waiting at least what Retry-After asked, cancellable. Every
// other transient error keeps the existing 2s/4s ladder. Partial output,
// cancellation, permanent errors and the one-shot context recovery are
// untouched (callModel decides those before asking here).

// retryMeta is the typed metadata a model error may carry (coremodel.HTTPError
// satisfies it). Keeping it an interface here avoids importing the provider
// package into core.
type retryMeta interface {
	StatusCode() int
	RateLimitedRetryAfter() (after time.Duration, gateExhausted bool)
}

// directRateLimitBudget bounds the total wait a client spends on its own for
// provider 429s without a Gate: enough for one short window, never a second
// ladder on top of a Gate's.
const directRateLimitBudget = 60 * time.Second

// directRateLimitWait is the floor wait between direct 429 retries when the
// provider gave no Retry-After.
const directRateLimitWait = 5 * time.Second

// modelRetrySleep is the one place callModel sleeps between attempts; tests
// replace it to avoid real time.
var modelRetrySleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// modelRetryPlan decides whether to try again and how long to wait first.
// attempt is 0-based (the attempt that just failed), waitedRateLimit is the
// time already spent waiting for rate limits in this call.
func modelRetryPlan(err error, attempt int, waitedRateLimit time.Duration, base time.Duration) (wait time.Duration, retry bool, rateLimited bool) {
	var meta retryMeta
	if errors.As(err, &meta) && meta.StatusCode() == http.StatusTooManyRequests {
		after, exhausted := meta.RateLimitedRetryAfter()
		if exhausted {
			return 0, false, true // the Gate already waited for us: final
		}
		wait = directRateLimitWait
		if after > wait {
			wait = after
		}
		if waitedRateLimit+wait > directRateLimitBudget {
			return 0, false, true
		}
		return wait, true, true
	}
	if permanent(err) {
		return 0, false, false
	}
	wait = time.Duration(attempt+1) * base
	if wait < 0 {
		wait = 0
	}
	return wait, true, false
}
