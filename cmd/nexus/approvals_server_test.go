package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestApprovalListenerPolicy(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:18082", "[::1]:18083"} {
		if !approvalListenAddress(addr) {
			t.Errorf("rejected %s", addr)
		}
	}
	for _, addr := range []string{"", "localhost:18082", ":18082", "0.0.0.0:18082", "192.0.2.1:18082", "127.0.0.1:0", "127.0.0.1:65536", "[::]:18082"} {
		if approvalListenAddress(addr) {
			t.Errorf("accepted %s", addr)
		}
	}
}

func TestApprovalListenersSeparateAndStop(t *testing.T) {
	p, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	public, admin := http.NewServeMux(), http.NewServeMux()
	public.HandleFunc("/change/approve", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	admin.HandleFunc("/v1/changes", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveApprovalListeners(ctx, p, a, public, admin) }()
	client := &http.Client{Timeout: time.Second}
	for _, test := range []struct {
		addr, path string
		want       int
	}{
		{p.Addr().String(), "/v1/changes", 404},
		{a.Addr().String(), "/change/approve", 404},
		{p.Addr().String(), "/change/approve", 204},
		{a.Addr().String(), "/v1/changes", 202},
	} {
		res, err := client.Get("http://" + test.addr + test.path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != test.want {
			t.Errorf("%s: got %d", test.path, res.StatusCode)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("shutdown timeout")
	}
}
