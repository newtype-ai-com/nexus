package nexus

import "github.com/newtype-ai-com/nexus/ids"

func cloneQuota(q AccountQuota) AccountQuota {
	r := make(map[string]QuotaRequest, len(q.Requests))
	for k, v := range q.Requests {
		r[k] = v
	}
	q.Requests = r
	return q
}
func (t *memTx) AccountQuota(account ids.Account, month string) (AccountQuota, error) {
	if err := t.check(false); err != nil {
		return AccountQuota{}, err
	}
	q, ok := t.data.quotas[string(account)+":"+month]
	if !ok {
		return AccountQuota{}, ErrNotFound
	}
	return cloneQuota(q), nil
}
func (t *memTx) PutAccountQuota(q AccountQuota) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindAccount, string(q.AccountID)) != nil || q.Used < 0 || q.Increase < 0 || q.BaseLimit < 0 {
		return ErrInvalid
	}
	t.data.quotas[string(q.AccountID)+":"+q.Month] = cloneQuota(q)
	return nil
}
