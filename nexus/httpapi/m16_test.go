package httpapi

import (
	"github.com/newtype-ai-com/nexus/nexus"
	"net/http/httptest"
	"testing"
)

func TestM16RunnerUnavailablePublicLabel(t *testing.T) {
	w := httptest.NewRecorder()
	fail(w, nexus.ErrRunnerUnavailable)
	if w.Code != 409 || w.Body.String() != "{\"error\":\"runner_unavailable_specify_live_session\"}\n" {
		t.Fatal(w.Code, w.Body.String())
	}
}
