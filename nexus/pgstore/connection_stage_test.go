package pgstore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
)

func TestConnectionStageRedacts(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want string
	}{
		{errors.New("SYNTHETIC-SECRET"), "connect"},
		{&pgconn.PgError{Code: "28P01", Message: "SYNTHETIC-SECRET"}, "authentication"},
		{x509.HostnameError{Host: "SYNTHETIC-SECRET"}, "tls_verification"},
		{context.DeadlineExceeded, "timeout"},
		{stageError("set_role"), "set_role"},
		{stageError("verify_role"), "verify_role"},
	} {
		e := fmt.Errorf("SYNTHETIC-SECRET: %w", tt.err)
		got := ConnectionStage(e)
		if got != tt.want || strings.Contains(stageError(got).Error(), "SYNTHETIC-SECRET") {
			t.Fatalf("stage %s want %s", got, tt.want)
		}
	}
}
