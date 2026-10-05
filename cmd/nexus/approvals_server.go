package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// approvalListenAddress deliberately accepts only literal loopback addresses.
// The public listener is published by a separately approved HTTPS proxy; the
// administrative listener must never be an ingress target.
func approvalListenAddress(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	n, parseErr := strconv.Atoi(port)
	return err == nil && parseErr == nil && ip != nil && ip.IsLoopback() && n > 0 && n <= 65535
}

func approvalHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
}

// Both sockets are acquired before serving either surface. A failed admin bind
// must not leave an unattended public approval service running.
func serveApprovalSurfaces(ctx context.Context, publicAddr, adminAddr string, public, admin http.Handler) error {
	if !approvalListenAddress(publicAddr) || !approvalListenAddress(adminAddr) || publicAddr == adminAddr || public == nil || admin == nil {
		return errors.New("nexus: invalid approval listener configuration")
	}
	p, err := net.Listen("tcp", publicAddr)
	if err != nil {
		return errors.New("nexus: approval public listen failed")
	}
	defer p.Close()
	a, err := net.Listen("tcp", adminAddr)
	if err != nil {
		return errors.New("nexus: approval admin listen failed")
	}
	defer a.Close()
	return serveApprovalListeners(ctx, p, a, public, admin)
}

func serveApprovalListeners(ctx context.Context, p, a net.Listener, public, admin http.Handler) error {
	servers := []*http.Server{approvalHTTPServer(public), approvalHTTPServer(admin)}
	for _, srv := range servers {
		srv.BaseContext = func(net.Listener) context.Context { return ctx }
	}
	failed := make(chan error, 2)
	go func() { failed <- servers[0].Serve(p) }()
	go func() { failed <- servers[1].Serve(a) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-failed:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if srv.Shutdown(shutdown) != nil {
			_ = srv.Close()
		}
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("nexus: approval HTTP server failed")
	}
	return nil
}
