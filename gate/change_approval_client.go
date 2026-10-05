package gate

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ChangeApprovals is the owner email change-approval facility (ChangeHandler)
// seen from a server that wants to perform an approved operator change. It
// can only request, observe, consume and report; it can never decide.
type ChangeApprovals interface {
	Begin(context.Context, ChangeInput) (ChangeApproval, error)
	Get(context.Context, string) (ChangeApproval, error)
	Consume(context.Context, string, string) (ChangeApproval, error)
	Result(context.Context, string, string) (ChangeApproval, error)
}

// ChangeAdminClient talks to the approvals process admin surface
// (`nexus approvals`, POST /v1/changes ...). Plain HTTP is accepted only for a
// literal loopback address, matching where that surface listens.
type ChangeAdminClient struct {
	base  string
	token string
	http  *http.Client
}

func NewChangeAdminClient(base, token string, transport http.RoundTripper) (*ChangeAdminClient, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(token) < 32 || strings.ContainsAny(token, " \r\n\x00") {
		return nil, ErrChangeInvalid
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return nil, ErrChangeInvalid
		}
	default:
		return nil, ErrChangeInvalid
	}
	return &ChangeAdminClient{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *ChangeAdminClient) do(ctx context.Context, method, path string, in any) (ChangeApproval, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return ChangeApproval{}, ErrChangeInvalid
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return ChangeApproval{}, ErrChangeInvalid
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return ChangeApproval{}, ErrChangeStorage
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return ChangeApproval{}, ErrChangeStorage
	}
	switch {
	case res.StatusCode == 200 || res.StatusCode == 202:
	case res.StatusCode == 400:
		return ChangeApproval{}, ErrChangeInvalid
	case res.StatusCode == 404:
		return ChangeApproval{}, ErrChangeNotFound
	case res.StatusCode == 409:
		return ChangeApproval{}, ErrChangeConflict
	case res.StatusCode == 429:
		return ChangeApproval{}, ErrChangeLimit
	default:
		return ChangeApproval{}, ErrChangeStorage
	}
	var out ChangeApproval
	if json.Unmarshal(raw, &out) != nil || !strings.HasPrefix(out.ID, "car_") {
		return ChangeApproval{}, ErrChangeStorage
	}
	return out, nil
}

func (c *ChangeAdminClient) Begin(ctx context.Context, in ChangeInput) (ChangeApproval, error) {
	return c.do(ctx, "POST", "/v1/changes", in)
}
func (c *ChangeAdminClient) Get(ctx context.Context, id string) (ChangeApproval, error) {
	if !validChangeID(id) {
		return ChangeApproval{}, ErrChangeNotFound
	}
	return c.do(ctx, "GET", "/v1/changes/"+id, nil)
}
func (c *ChangeAdminClient) Consume(ctx context.Context, id, manifest string) (ChangeApproval, error) {
	if !validChangeID(id) {
		return ChangeApproval{}, ErrChangeNotFound
	}
	return c.do(ctx, "POST", "/v1/changes/"+id+"/consume", map[string]string{"manifest": manifest})
}
func (c *ChangeAdminClient) Result(ctx context.Context, id, result string) (ChangeApproval, error) {
	if !validChangeID(id) {
		return ChangeApproval{}, ErrChangeNotFound
	}
	return c.do(ctx, "POST", "/v1/changes/"+id+"/result", map[string]string{"result": result})
}

func validChangeID(id string) bool {
	if len(id) != 68 || !strings.HasPrefix(id, "car_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}
