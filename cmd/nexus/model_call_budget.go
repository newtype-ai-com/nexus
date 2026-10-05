package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
)

// Offline provisioning only; no DB/env/HTTP and no implicit reset. Creation is
// a separately approved operator action, never part of serve startup.
func runModelCallBudgetInit(args []string) error {
	invalid := errors.New("nexus: call-budget-init requires --file, --rollout, --max-calls, --expires-at and --confirm")
	fs := flag.NewFlagSet("call-budget-init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("file", "", "new private ledger path")
	rollout := fs.String("rollout", "", "approved rollout identifier")
	max := fs.Int64("max-calls", 0, "total upstream POST attempts")
	expires := fs.String("expires-at", "", "RFC3339 expiry")
	confirm := fs.Bool("confirm", false, "explicitly create a new ledger")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !*confirm || *path == "" {
		return invalid
	}
	deadline, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		return invalid
	}
	if gate.InitializeModelCallBudget(*path, gate.ModelCallBudgetHeader{Version: 1, Rollout: *rollout, MaxCalls: *max, ExpiresAt: deadline}) != nil {
		return errors.New("nexus: call budget initialization refused")
	}
	return nil
}

// Offline read-only check. Expected header flags bind the inspected file to a
// reviewed plan; they do not attest to the active server configuration.
func runModelCallBudgetStatus(args []string, output io.Writer) error {
	invalid := errors.New("nexus: call-budget-status requires --file, --rollout, --max-calls and --expires-at")
	fs := flag.NewFlagSet("call-budget-status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("file", "", "existing private ledger path")
	rollout := fs.String("rollout", "", "expected rollout identifier")
	max := fs.Int64("max-calls", 0, "expected total attempts")
	expires := fs.String("expires-at", "", "expected RFC3339 expiry")
	ready := fs.Bool("require-ready", false, "fail when expired or exhausted")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *path == "" || *rollout == "" || *max <= 0 {
		return invalid
	}
	deadline, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		return invalid
	}
	status, err := gate.InspectModelCallBudget(*path)
	if err != nil || status.Header.Rollout != *rollout || status.Header.MaxCalls != *max || !status.Header.ExpiresAt.Equal(deadline) {
		return errors.New("nexus: call budget inspection refused or header mismatch")
	}
	if *ready && (status.Expired || status.Remaining == 0) {
		return errors.New("nexus: call budget expired or exhausted")
	}
	result := struct {
		gate.ModelCallBudgetStatus
		ExecutionAuthorized bool `json:"execution_authorized"`
		ServerVerified      bool `json:"server_verified"`
	}{ModelCallBudgetStatus: status}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("nexus: call budget status output failed")
	}
	return nil
}
