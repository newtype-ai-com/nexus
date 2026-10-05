package nexusserver

import (
	"net/http"
	"testing"
)

// A deployment that uses host networking
// must bind loopback only; the default stays all interfaces inside a container.
func TestBindHostLoopbackOnly(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1", "PORT": "18083"}
	get := func(k string) string { return base[k] }
	cfg, err := ConfigFromEnv(get)
	if err != nil || cfg.BindHost != "" || HTTPServerOn(cfg.BindHost, cfg.Port, http.NotFoundHandler()).Addr != ":18083" {
		t.Fatalf("default bind changed: %+v %v", cfg.BindHost, err)
	}
	for host, want := range map[string]string{"127.0.0.1": "127.0.0.1:18083", "::1": "[::1]:18083"} {
		base["NEXUS_BIND_HOST"] = host
		cfg, err := ConfigFromEnv(get)
		if err != nil || HTTPServerOn(cfg.BindHost, cfg.Port, http.NotFoundHandler()).Addr != want {
			t.Fatalf("%s: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "203.0.113.10", "localhost", "127.0.0.1:1", " 127.0.0.1", "127.000.000.001", "::ffff:127.0.0.1"} {
		base["NEXUS_BIND_HOST"] = host
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatalf("%q accepted", host)
		}
	}
	if HTTPServer("8080", http.NotFoundHandler()).Addr != ":8080" {
		t.Fatal("HTTPServer must keep binding all interfaces")
	}
}
