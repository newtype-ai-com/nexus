package core

import "context"

// WaitIdle returns once no turn is active: the current turn (if any) has
// finished and its record was saved (saveTurn runs before the turn is
// cleared). It starts nothing and cancels nothing; a restart at a turn
// boundary uses it so the answer in flight is never cut off.
func (e *Engine) WaitIdle(ctx context.Context) error {
	for {
		e.mu.Lock()
		t := e.active
		e.mu.Unlock()
		if t == nil {
			return nil
		}
		select {
		case <-t.finished:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// noteSave records the outcome of the latest turn save of a conversation
// (requires e.mu).
func (e *Engine) noteSave(id string, err error) {
	if e.saveResults == nil {
		e.saveResults = map[string]error{}
	}
	e.saveResults[id] = err
}

// LastSave reports the latest turn save of a conversation in this process:
// saved is true when it succeeded; err is the failure; both zero when no turn
// of it was saved here (nothing new to confirm). A restart carries this
// confirmed outcome instead of treating idleness as proof of a save.
func (e *Engine) LastSave(id string) (saved bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	err, ok := e.saveResults[id]
	return ok && err == nil, err
}
