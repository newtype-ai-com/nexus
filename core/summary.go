package core

import (
	"context"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// Compaction is a real paid model invocation too. It gets its own trace ID and
// usage record, but is attempted only once, not through normal retry policy.
type summaryModel struct {
	turn  *turn
	round int
}

func (s summaryModel) Chat(ctx context.Context, request ModelRequest, onToken func(string)) (ModelResponse, error) {
	request.InvocationID = ids.New(ids.KindInvocation)
	started := time.Now()
	response, err := (executionModel{engine: s.turn.engine}).Chat(ctx, request, onToken)
	record := InvocationRecord{ID: request.InvocationID, Purpose: "summary", At: started.UTC(), Round: s.round, MS: time.Since(started).Milliseconds(), Usage: response.Usage}
	if err != nil {
		record.Error = clipText(clean(err.Error()), 300)
	}
	s.turn.record.Invocations = append(s.turn.record.Invocations, record)
	return response, err
}
