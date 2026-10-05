package httpapi

import (
	"context"
	"encoding/json"
	"math"
	"sync"

	"github.com/newtype-ai-com/nexus/core"
)

// NewMeteredCoreRunner uses the same isolated, model-only execution boundary as
// NewCoreRunner. It accumulates provider-reported input/output usage for every
// attempt. Missing, invalid or failed-attempt usage is unknown (-1): the durable
// executor retains its full admission ceiling rather than promising a refund.
// Provider usage is not an invoice; monetary settlement remains out of scope.
func NewMeteredCoreRunner(cfg CoreRunnerConfig) (MeteredRunner, error) {
	if _, err := NewCoreRunner(cfg); err != nil {
		return nil, err
	}
	return func(ctx context.Context, action string, raw json.RawMessage) (int64, error) {
		meter := &usageModel{Model: cfg.Model}
		local := cfg
		local.Model = meter
		run, err := NewCoreRunner(local)
		if err != nil {
			return -1, err
		}
		err = run(ctx, action, raw)
		meter.mu.Lock()
		defer meter.mu.Unlock()
		if meter.unknown {
			return -1, err
		}
		return meter.total, err
	}, nil
}

type usageModel struct {
	core.Model
	mu      sync.Mutex
	total   int64
	unknown bool
}

func (m *usageModel) Chat(ctx context.Context, req core.ModelRequest, token func(string)) (core.ModelResponse, error) {
	out, err := m.Model.Chat(ctx, req, token)
	m.mu.Lock()
	defer m.mu.Unlock()
	// Cache totals vary across providers. Prefer explicit prompt-total when
	// supplied; add separately reported cache writes/reads otherwise.
	u := out.Usage
	input := int64(u.InputTokens)
	if u.PromptTotalTokens > 0 {
		input = int64(u.PromptTotalTokens)
	} else {
		for _, n := range []int{u.CacheReadTokens, u.CacheWriteTokens} {
			if n < 0 || input > math.MaxInt64-int64(n) {
				m.unknown = true
			} else {
				input += int64(n)
			}
		}
	}
	output := int64(u.OutputTokens)
	if err != nil || u.InputTokens < 0 || u.OutputTokens < 0 || u.PromptTotalTokens < 0 || u.CacheReadTokens < 0 || u.CacheWriteTokens < 0 || u.ReasoningTokens < 0 || input > math.MaxInt64-output || input+output <= 0 {
		m.unknown = true
	} else if m.total > math.MaxInt64-(input+output) {
		m.unknown = true
	} else {
		m.total += input + output
	}
	return out, err
}
