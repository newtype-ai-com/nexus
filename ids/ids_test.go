package ids

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVectors(t *testing.T) {
	if got := encode(0, [10]byte{}); got != "00000000000000000000000000" {
		t.Fatal(got)
	}
	var all [10]byte
	for i := range all {
		all[i] = 255
	}
	if got := encode(0, all); got != "0000000000ZZZZZZZZZZZZZZZZ" {
		t.Fatal(got)
	}
}
func TestMonotonic(t *testing.T) {
	g := generator{}
	at := time.UnixMilli(123456789)
	last := ""
	for i := 0; i < 2000; i++ {
		id := g.new(KindSession, at.Add(-time.Duration(i)*time.Millisecond))
		if err := Check(KindSession, id); err != nil {
			t.Fatal(err)
		}
		if id <= last {
			t.Fatalf("not ordered: %s <= %s", id, last)
		}
		got, err := Time(id)
		if err != nil || !got.Equal(at) {
			t.Fatalf("time %v %v", got, err)
		}
		last = id
	}
}
func TestEntropyOverflow(t *testing.T) {
	g := generator{ms: 10, initialized: true}
	for i := range g.entropy {
		g.entropy[i] = 255
	}
	id := g.new(KindEvent, time.UnixMilli(9))
	at, err := Time(id)
	if err != nil || at.UnixMilli() != 11 {
		t.Fatalf("%v %v", at, err)
	}
}
func TestConcurrent(t *testing.T) {
	ch := make(chan string, 4000)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				ch <- New(KindEvent)
			}
		}()
	}
	wg.Wait()
	close(ch)
	seen := map[string]bool{}
	for id := range ch {
		if seen[id] {
			t.Fatal("duplicate", id)
		}
		seen[id] = true
	}
	if len(seen) != 4000 {
		t.Fatal(len(seen))
	}
}
func TestInvalid(t *testing.T) {
	for _, id := range []string{"", "ses_00000000000000000000000000", "slv_0000000000000000000000000", "slv_80000000000000000000000000", "slv_0000000000000000000000000I", "slv_0000000000000000000000000L", "slv_deadbeef", "slv_" + strings.Repeat("z", 26)} {
		if !errors.Is(Check(KindSession, id), ErrInvalid) {
			t.Errorf("accepted %q", id)
		}
		if _, err := Time(id); !errors.Is(err, ErrInvalid) {
			t.Errorf("Time accepted %q", id)
		}
	}
	if _, err := ParseTask(New(KindSession)); err == nil {
		t.Fatal("type mismatch accepted")
	}
}
func TestDerive(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Millisecond)
	a := Derive(KindTask, at, "file:step")
	if a != Derive(KindTask, at, "file:step") || a == Derive(KindTask, at, "file:other") {
		t.Fatal("derive unstable")
	}
	b := Derive(KindSession, at, "file:step")
	if strings.Split(a, "_")[1] == strings.Split(b, "_")[1] {
		t.Fatal("kind not in hash")
	}
	got, err := Time(a)
	if err != nil || !got.Equal(at) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseTask(a); err != nil {
		t.Fatal(err)
	}
}
func TestKindsAndParsers(t *testing.T) {
	kinds := []Kind{KindAccount, KindSession, KindDelegation, KindTask, KindPolicy, KindEvent, KindApproval, KindRun, KindConv, KindAction, KindInvocation, KindLogin, KindAudit, KindProcess, KindDoc, KindTeam, KindSeat}
	for _, k := range kinds {
		id := New(k)
		if err := Check(k, id); err != nil {
			t.Fatal(err)
		}
		if got, ok := KindOf(id); !ok || got != k {
			t.Fatal(got, ok)
		}
	}
}
func TestTeamSeatParsers(t *testing.T) {
	team, seat := New(KindTeam), New(KindSeat)
	if _, err := ParseTeam(team); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSeat(seat); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTeam(seat); err == nil {
		t.Fatal("seat accepted as team")
	}
	if _, err := ParseSeat(New(KindSession)); err == nil {
		t.Fatal("session accepted as seat")
	}
}
func TestUnknownKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("missing panic")
		}
	}()
	New("unknown")
}
