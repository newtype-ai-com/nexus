package gate

import (
	"testing"
	"time"
)

// The public-API DB budget must cover a fresh pooler connection (2 s did not,
// 2026-10-04) and stay below the client's 5 s lease validate timeout.
func TestPublicAPIBudgetBetweenPoolerDialAndClientTimeout(t *testing.T) {
	if publicAPIBudget <= 2*time.Second || publicAPIBudget >= 5*time.Second {
		t.Fatalf("publicAPIBudget = %s, want > 2s and < 5s", publicAPIBudget)
	}
}
