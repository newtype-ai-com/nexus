package nexustransport

import (
	"context"
	"errors"
	"net/url"
	"regexp"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

var quotaID = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}_qtr_[0-9a-f]{64}$`)

func (c *Client) Quota(ctx context.Context, account string) (nexus.AccountQuota, error) {
	var q nexus.AccountQuota
	if account != "" && ids.Check(ids.KindAccount, account) != nil {
		return q, errors.New("invalid account ID")
	}
	err := c.Query(ctx, "/v1/quota", url.Values{"account_id": {account}}, &q)
	return q, err
}
func (c *Client) RequestQuota(ctx context.Context, account, client string, amount int64) (nexus.QuotaRequest, error) {
	var r nexus.QuotaRequest
	if amount <= 0 || len(client) < 1 || len(client) > 80 || (account != "" && ids.Check(ids.KindAccount, account) != nil) {
		return r, errors.New("invalid quota increase")
	}
	err := c.Do(ctx, "POST", "/v1/quota/requests", map[string]any{"account_id": account, "client_event_id": client, "amount": amount}, &r)
	return r, err
}
func (c *Client) QuotaRequest(ctx context.Context, account, id string) (nexus.QuotaRequest, error) {
	var r nexus.QuotaRequest
	if !quotaID.MatchString(id) || (account != "" && ids.Check(ids.KindAccount, account) != nil) {
		return r, errors.New("invalid quota request ID")
	}
	err := c.Query(ctx, "/v1/quota/requests/"+id, url.Values{"account_id": {account}}, &r)
	return r, err
}
