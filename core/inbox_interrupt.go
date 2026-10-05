package core

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// watchHumanInterrupt cancels only the current tool batch. The turn survives so
// results are recorded before fresh inbox data reaches the next provider call.
// Stop joins the watcher; Tool.Run must honor cancellation and return normally.
func watchHumanInterrupt(parent context.Context, inbox ModelInbox, seen []string) (context.Context, func() bool) {
	ctx, cancel := context.WithCancel(parent)
	source, ok := inbox.(HumanInterruptInbox)
	if !ok {
		return ctx, func() bool { cancel(); return false }
	}
	known := make(map[string]bool, len(seen))
	for _, id := range seen {
		known[id] = true
	}
	var interrupted atomic.Bool
	check := func() bool {
		ids, err := source.HumanInterrupts(ctx)
		if ctx.Err() != nil {
			return true
		}
		// A failed authenticated queue cannot safely permit an old batch
		// to continue. The next loop reads it again and fails closed. A queue
		// that has not reconciled yet has shown this turn no mail at all, so
		// there is no batch to protect from newer mail: it is no interrupt.
		stop := err != nil && !errors.Is(err, ErrInboxUnavailable)
		for _, id := range ids {
			stop = stop || (id != "" && !known[id])
		}
		if stop {
			interrupted.Store(true)
			cancel()
		}
		return stop
	}
	// Check synchronously: mail arriving during Chat must prevent even the first
	// fast tool in the stale batch, regardless of goroutine scheduling.
	if check() {
		return ctx, func() bool { cancel(); return interrupted.Load() }
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if check() {
					return
				}
			}
		}
	}()
	return ctx, func() bool {
		cancel()
		<-done
		return interrupted.Load()
	}
}
