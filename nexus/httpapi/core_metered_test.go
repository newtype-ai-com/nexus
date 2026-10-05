package httpapi

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/newtype-ai-com/nexus/core"
)

type usageFixture struct {
	u   core.Usage
	err error
}

func (m usageFixture) Chat(context.Context, core.ModelRequest, func(string)) (core.ModelResponse, error) {
	return core.ModelResponse{Usage: m.u}, m.err
}
func TestUsageMeterConservativeAccounting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		u       core.Usage
		err     error
		total   int64
		unknown bool
	}{
		{"inclusive cache", core.Usage{InputTokens: 11, OutputTokens: 4, PromptTotalTokens: 11, CacheReadTokens: 5}, nil, 15, false},
		{"separate cache", core.Usage{InputTokens: 11, OutputTokens: 4, CacheReadTokens: 5, CacheWriteTokens: 2}, nil, 22, false},
		{"no usage", core.Usage{}, nil, 0, true},
		{"failed attempt", core.Usage{InputTokens: 11}, errors.New("private"), 0, true},
		{"negative", core.Usage{InputTokens: -1, OutputTokens: 4}, nil, 0, true},
		{"overflow", core.Usage{InputTokens: math.MaxInt, OutputTokens: math.MaxInt}, nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &usageModel{Model: usageFixture{tc.u, tc.err}}
			m.Chat(context.Background(), core.ModelRequest{}, nil)
			if m.total != tc.total || m.unknown != tc.unknown {
				t.Fatal(m.total, m.unknown)
			}
		})
	}
	m := &usageModel{Model: usageFixture{u: core.Usage{InputTokens: 2, OutputTokens: 3}}}
	for i := 0; i < 3; i++ {
		m.Chat(context.Background(), core.ModelRequest{}, nil)
	}
	if m.total != 15 {
		t.Fatal("attempt usage not accumulated")
	}
}
