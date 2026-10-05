package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
)

// ownerCodeIssuer is the store operation enrol-owner needs (a seam for tests).
type ownerCodeIssuer interface {
	BeginOwnerCode(context.Context, string, time.Time) (gate.Enrolment, string, error)
}

// runEnrolOwner is the operator-only, mail-free owner bootstrap (self-host G4).
// It runs where the server's configuration and database live (for example
// `docker compose run --rm nexus enrol-owner`), never as an HTTP route. The
// one-time code goes to this terminal only; nothing is logged.
func runEnrolOwner(ctx context.Context, cfg nexusserver.Config, store ownerCodeIssuer, out io.Writer) error {
	if !cfg.OwnerCode {
		return errors.New("nexus: enrol-owner is off; set NEXUS_OWNER_CODE=1 (self-host only) and restart nexus")
	}
	if !gate.ValidOwnerEmail(cfg.OwnerEmail) || cfg.EnrolmentConfig == nil {
		return errors.New("nexus: enrol-owner requires NEXUS_OWNER_EMAIL and the enrolment settings (BASE_URL, ENROL_ALLOW)")
	}
	e, code, err := store.BeginOwnerCode(ctx, cfg.OwnerEmail, time.Now())
	if err != nil {
		return errors.New("nexus: owner code unavailable")
	}
	fmt.Fprintf(out, "One-time owner code for %s (single use, expires %s):\n%s\n\nOn the owner's computer:\n  newtype auth enrol --gate-url %s --code\n  (paste the code at the hidden prompt; never as a command argument)\n", cfg.OwnerEmail, e.Expires.UTC().Format(time.RFC3339), code, cfg.EnrolmentConfig.BaseURL)
	return nil
}
