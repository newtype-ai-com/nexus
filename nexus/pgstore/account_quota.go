package pgstore

import (
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func (t *transaction) AccountQuota(account ids.Account, month string) (nexus.AccountQuota, error) {
	return one[nexus.AccountQuota](t, `SELECT body FROM account_quotas WHERE account_id=$1 AND month=$2`, string(account), month)
}
func (t *transaction) PutAccountQuota(q nexus.AccountQuota) error {
	if !valid(ids.KindAccount, string(q.AccountID)) || q.Used < 0 || q.BaseLimit < 0 || q.Increase < 0 {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO account_quotas(account_id,month,body) VALUES($1,$2,$3) ON CONFLICT(account_id,month) DO UPDATE SET body=EXCLUDED.body`, q, string(q.AccountID), q.Month)
}
