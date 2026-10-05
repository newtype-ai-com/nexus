package pgstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// TSC-R3: an install that already had the earlier reverse index
// message_edges_b(account_id,b) is upgraded by Migrate to the ordered
// message_edges_reverse(account_id,b,a), and the bounded reverse lookup of a
// high-degree session reads that index instead of sorting the incident set.
func TestPostgresMessageEdgeIndexUpgrade(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := s.Pool()
	// the earlier schema-9 state
	if _, err := pool.Exec(ctx, `DROP INDEX IF EXISTS message_edges_reverse; DROP INDEX IF EXISTS message_edges_b; CREATE INDEX message_edges_b ON message_edges(account_id,b)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	defs := map[string]string{}
	rows, err := pool.Query(ctx, `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'message_edges'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n, d string
		if err := rows.Scan(&n, &d); err != nil {
			t.Fatal(err)
		}
		defs[n] = d
	}
	rows.Close()
	if _, old := defs["message_edges_b"]; old {
		t.Fatal("earlier index kept:", defs)
	}
	if !strings.Contains(defs["message_edges_reverse"], "(account_id, b, a)") {
		t.Fatalf("ordered reverse index missing: %v", defs)
	}
	// a high-degree session: many edges where it is the b side
	account := string(ids.New(ids.KindAccount))
	hub := "slv_ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	if _, err := pool.Exec(ctx, `INSERT INTO message_edges(account_id,a,b,last_at)
 SELECT $1, 'slv_' || lpad(g::text, 26, '0'), $2, now() FROM generate_series(1, 5000) g`, account, hub); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ANALYZE message_edges`); err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	prow, err := pool.Query(ctx, `EXPLAIN SELECT a AS s FROM message_edges WHERE account_id=$1 AND b=$2 ORDER BY a LIMIT 257`, account, hub)
	if err != nil {
		t.Fatal(err)
	}
	for prow.Next() {
		var line string
		if err := prow.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	prow.Close()
	if !strings.Contains(plan.String(), "message_edges_reverse") || strings.Contains(plan.String(), "Sort") {
		t.Fatalf("reverse lookup does not read the ordered index:\n%s", plan.String())
	}
	t.Logf("reverse lookup plan:\n%s", plan.String())
}
