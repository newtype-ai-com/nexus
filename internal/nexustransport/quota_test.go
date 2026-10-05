package nexustransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
)

func TestQuotaRoutesAndExactInteger(t *testing.T) {
	account := ids.New(ids.KindAccount)
	id := "2026-10_qtr_" + strings.Repeat("a", 64)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("authentication missing")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/quota", "GET /v1/quota/requests/" + id:
			if r.URL.Query().Get("account_id") != account {
				t.Error("account query lost")
			}
		case "POST /v1/quota/requests":
			var body struct {
				Account string `json:"account_id"`
				Amount  int64  `json:"amount"`
				Client  string `json:"client_event_id"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Amount != 9007199254740993 || body.Account != account || body.Client != "stable" {
				t.Error(body)
			}
		default:
			t.Error("wrong route")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c, err := New(server.URL, Auth{Token: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = c.Quota(ctx, account); err != nil {
		t.Fatal(err)
	}
	if _, err = c.RequestQuota(ctx, account, "stable", 9007199254740993); err != nil {
		t.Fatal(err)
	}
	if _, err = c.QuotaRequest(ctx, account, id); err != nil {
		t.Fatal(err)
	}
	if _, err = c.QuotaRequest(ctx, account, "../secrets"); err == nil {
		t.Fatal("invalid path accepted")
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
