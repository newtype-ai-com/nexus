package redact

import (
	"strings"
	"testing"
)

func TestUserApprovalCapabilityRedacted(t *testing.T) {
	token := "uap_" + strings.Repeat("a", 64)
	out, n := Text("https://gate.example.test/users/approve?t=" + token)
	if n != 1 || strings.Contains(out, token) {
		t.Fatal("approval capability leaked")
	}
}
