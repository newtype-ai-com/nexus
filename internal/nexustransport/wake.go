package nexustransport

import (
	"net/http"
	"net/url"
)

// WakeSignal coalesces hints. It conveys no content, identity or permissions.
// A single receiver drains it and performs authenticated reconciliation.
type WakeSignal struct{ ch chan struct{} }

func NewWakeSignal() *WakeSignal { return &WakeSignal{ch: make(chan struct{}, 1)} }
func (w *WakeSignal) Notify() {
	if w == nil {
		return
	}
	select {
	case w.ch <- struct{}{}:
	default:
	}
}
func (w *WakeSignal) Events() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.ch
}

// WakeTransport only observes the configured origin and authenticated responses.
// It never changes requests or follows redirects. The hint cannot start a model.
type WakeTransport struct {
	Base   http.RoundTripper
	Origin string
	Signal *WakeSignal
}

func (t WakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(r)
	if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 && r.Header.Get("Authorization") != "" {
		u, parseErr := url.Parse(t.Origin)
		if parseErr == nil && u.Scheme == r.URL.Scheme && u.Host == r.URL.Host && resp.Header.Get("X-Newtype-Wake") == "1" {
			t.Signal.Notify()
		}
	}
	return resp, err
}
