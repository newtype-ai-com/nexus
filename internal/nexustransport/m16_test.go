package nexustransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestM16PublicGuidanceOnly(t *testing.T) {
	for _, tc := range []struct {
		body     string
		guidance bool
	}{
		{`{"error":"runner_unavailable_specify_live_session"}`, true},
		{`{"error":"PRIVATE BODY"}`, false},
		{`{"error":"runner_unavailable_specify_live_session PRIVATE"}`, false},
		{strings.Repeat("x", 1025), false},
	} {
		calls := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(409); w.Write([]byte(tc.body)) }))
		c, err := New(s.URL, Auth{Token: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Do(context.Background(), "POST", "/v1/delegations", struct{}{}, nil)
		s.Close()
		if err == nil || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "Hand the work to a session that runs — name it with to (hub_peers lists them) — or do it yourself") != tc.guidance || calls != 1 {
			t.Fatal(err, calls)
		}
	}
}
