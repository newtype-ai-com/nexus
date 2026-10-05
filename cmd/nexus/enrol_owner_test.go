package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
)

type fakeOwnerCodes struct{ owner string }

func (f *fakeOwnerCodes) BeginOwnerCode(_ context.Context, owner string, now time.Time) (gate.Enrolment, string, error) {
	f.owner = owner
	return gate.Enrolment{Email: owner, Expires: now.Add(gate.OwnerCodeTTL)}, "eoc_" + strings.Repeat("ab", 32), nil
}

func TestEnrolOwnerOffWithoutOwnerCode(t *testing.T) {
	err := runEnrolOwner(context.Background(), nexusserver.Config{OwnerEmail: "boss@selfhost.test", EnrolmentConfig: &gate.EnrolmentConfig{BaseURL: "https://x.test"}}, &fakeOwnerCodes{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "NEXUS_OWNER_CODE=1") {
		t.Fatal(err)
	}
}

func TestEnrolOwnerPrintsCodeForConfiguredOwnerOnly(t *testing.T) {
	ec := &gate.EnrolmentConfig{BaseURL: "https://nexus.selfhost.test"}
	for _, cfg := range []nexusserver.Config{{}, {OwnerEmail: "boss@selfhost.test", OwnerCode: true}, {OwnerEmail: "", EnrolmentConfig: ec, OwnerCode: true}, {OwnerEmail: "boss@selfhost.test", EnrolmentConfig: ec}} {
		f := &fakeOwnerCodes{}
		if runEnrolOwner(context.Background(), cfg, f, &bytes.Buffer{}) == nil || f.owner != "" {
			t.Fatalf("issued without owner+enrolment: %+v", cfg)
		}
	}
	f := &fakeOwnerCodes{}
	var out bytes.Buffer
	if err := runEnrolOwner(context.Background(), nexusserver.Config{OwnerEmail: "boss@selfhost.test", EnrolmentConfig: ec, OwnerCode: true}, f, &out); err != nil {
		t.Fatal(err)
	}
	if f.owner != "boss@selfhost.test" || !strings.Contains(out.String(), "eoc_"+strings.Repeat("ab", 32)) || !strings.Contains(out.String(), "newtype auth enrol --gate-url https://nexus.selfhost.test --code") {
		t.Fatal(out.String())
	}
}
