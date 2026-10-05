package nexustransport

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type wakeRoundTrip func(*http.Request) (*http.Response, error)

func (f wakeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWakeTransportBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, origin, authorization, hint string
		status                            int
		fail, want                        bool
	}{
		{"authenticated", "https://gate.example", "Bearer fixture", "1", 200, false, true},
		{"path base", "https://gate.example/api", "Bearer fixture", "1", 200, false, true},
		{"other origin", "https://other.example", "Bearer fixture", "1", 200, false, false},
		{"scheme", "http://gate.example", "Bearer fixture", "1", 200, false, false},
		{"no auth", "https://gate.example", "", "1", 200, false, false},
		{"redirect", "https://gate.example", "Bearer fixture", "1", 302, false, false},
		{"denied", "https://gate.example", "Bearer fixture", "1", 403, false, false},
		{"wrong hint", "https://gate.example", "Bearer fixture", "true", 200, false, false},
		{"transport error", "https://gate.example", "Bearer fixture", "1", 200, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := NewWakeSignal()
			base := wakeRoundTrip(func(r *http.Request) (*http.Response, error) {
				if tc.fail {
					return nil, errors.New("fixture")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"X-Newtype-Wake": []string{tc.hint}}, Body: io.NopCloser(strings.NewReader("content untouched"))}, nil
			})
			r, _ := http.NewRequest("GET", "https://gate.example/v1/inbox", nil)
			r.Header.Set("Authorization", tc.authorization)
			tr := WakeTransport{Base: base, Origin: tc.origin, Signal: signal}
			for i := 0; i < 2; i++ {
				res, _ := tr.RoundTrip(r)
				if res != nil {
					data, _ := io.ReadAll(res.Body)
					res.Body.Close()
					if string(data) != "content untouched" {
						t.Fatal("body consumed")
					}
				}
			}
			got := false
			select {
			case <-signal.Events():
				got = true
			default:
			}
			if got != tc.want {
				t.Fatalf("wake=%v want=%v", got, tc.want)
			}
			select {
			case <-signal.Events():
				t.Fatal("hints not coalesced")
			default:
			}
		})
	}
}
