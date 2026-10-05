package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/newtype-ai-com/nexus/gate"
)

type approvalsConfig struct {
	base, owner, key, from, admin, path, publicAddr, adminAddr string
	max                                                        int
}

func approvalsConfigFromEnv(get func(string) string) (approvalsConfig, error) {
	c := approvalsConfig{base: get("BASE_URL"), owner: strings.ToLower(strings.TrimSpace(get("NEXUS_OWNER_EMAIL"))), key: get("RESEND_API_KEY"), from: get("MAIL_FROM"), admin: get("ADMIN_TOKEN"), path: get("APPROVALS_STORE"), publicAddr: get("APPROVALS_PUBLIC_ADDR"), adminAddr: get("APPROVALS_ADMIN_ADDR")}
	n, e := strconv.Atoi(get("APPROVALS_MAX_REQUESTS"))
	c.max = n
	if e != nil || n < 1 || n > 10000 || !approvalListenAddress(c.publicAddr) || !approvalListenAddress(c.adminAddr) || c.publicAddr == c.adminAddr || !gate.ValidOwnerEmail(c.owner) || c.key == "" || c.from == "" || len(c.admin) < 32 || c.path == "" {
		return c, errors.New("nexus: invalid approvals configuration")
	}
	return c, nil
}
func runApprovals(ctx context.Context, get func(string) string) error {
	c, e := approvalsConfigFromEnv(get)
	if e != nil {
		return e
	}
	mailer, e := gate.NewResendMailer(c.key, c.from)
	if e != nil {
		return errors.New("nexus: invalid approvals mail configuration")
	}
	store, e := gate.OpenFileChangeStore(c.path, c.max)
	if e != nil {
		return errors.New("nexus: approvals storage unavailable")
	}
	defer store.Close()
	audit, e := gate.NewAudit(os.Stderr)
	if e != nil {
		return errors.New("nexus: approvals audit unavailable")
	}
	defer audit.Close()
	h, e := gate.NewChangeHandler(gate.ChangeConfig{Store: store, Mailer: mailer, BaseURL: c.base, OwnerEmail: c.owner, AdminToken: c.admin, Audit: audit})
	if e != nil {
		return errors.New("nexus: invalid approvals handler configuration")
	}
	fmt.Fprintln(os.Stderr, "nexus: mode=approvals db=disabled model=disabled sealing=disabled owner_only=true public=loopback admin=loopback")
	return serveApprovalSurfaces(ctx, c.publicAddr, c.adminAddr, h.PublicHandler(), h.AdminHandler())
}
