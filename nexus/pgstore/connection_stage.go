package pgstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
)

// ConnectionStage returns only a fixed stage label, never an upstream message.
// Unknown transport errors intentionally remain connect rather than guessed TLS.
func ConnectionStage(err error) string {
	var stage *connectionStageError
	if errors.As(err, &stage) {
		return stage.stage
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "28P01" || pg.Code == "28000") {
		return "authentication"
	}
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) {
		return "tls_verification"
	}
	return "connect"
}

type connectionStageError struct{ stage string }

func (e *connectionStageError) Error() string {
	return "pgstore: database connection failed (" + e.stage + ")"
}
func stageError(stage string) error { return &connectionStageError{stage: stage} }
