// Package ids provides typed, monotonic ULID identifiers for Newtype Slaves.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindAccount    Kind = "nt"
	KindSession    Kind = "slv"
	KindDelegation Kind = "mnd"
	KindTask       Kind = "req"
	KindPolicy     Kind = "pol"
	KindEvent      Kind = "evt"
	KindApproval   Kind = "apr"
	KindRun        Kind = "run"
	KindConv       Kind = "cnv"
	KindAction     Kind = "act"
	KindInvocation Kind = "inv"
	KindLogin      Kind = "lgn"
	KindAudit      Kind = "aud"
	KindProcess    Kind = "prc"
	KindDoc        Kind = "doc"
	KindTeam       Kind = "tm"
	KindSeat       Kind = "st"
	// KindGrant: an execution grant for Nexus-originated turns (2026-10-04).
	KindGrant Kind = "xgr"
)
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const maxMillis = int64(1<<48 - 1)

var ErrInvalid = errors.New("invalid ID")

func known(k Kind) bool {
	switch k {
	case KindAccount, KindSession, KindDelegation, KindTask, KindPolicy, KindEvent, KindApproval, KindRun, KindConv, KindAction, KindInvocation, KindLogin, KindAudit, KindProcess, KindDoc, KindTeam, KindSeat, KindGrant:
		return true
	}
	return false
}
func KindOf(id string) (Kind, bool) {
	prefix, _, found := strings.Cut(id, "_")
	k := Kind(prefix)
	return k, found && known(k)
}
func Check(kind Kind, id string) error {
	k, ok := KindOf(id)
	if !ok || k != kind {
		return fmt.Errorf("%w: kind", ErrInvalid)
	}
	_, body, _ := strings.Cut(id, "_")
	if len(body) != 26 || body[0] > '7' {
		return fmt.Errorf("%w: ULID length or overflow", ErrInvalid)
	}
	for _, c := range body {
		if !strings.ContainsRune(alphabet, c) {
			return fmt.Errorf("%w: ULID alphabet", ErrInvalid)
		}
	}
	return nil
}
func Time(id string) (time.Time, error) {
	k, _ := KindOf(id)
	if err := Check(k, id); err != nil {
		return time.Time{}, err
	}
	_, body, _ := strings.Cut(id, "_")
	var ms int64
	for _, c := range body[:10] {
		ms = ms<<5 | int64(strings.IndexRune(alphabet, c))
	}
	return time.UnixMilli(ms).UTC(), nil
}
func encode(ms int64, entropy [10]byte) string {
	var raw [16]byte
	for i := 5; i >= 0; i-- {
		raw[i] = byte(ms)
		ms >>= 8
	}
	copy(raw[6:], entropy[:])
	n := new(big.Int).SetBytes(raw[:])
	mask := big.NewInt(31)
	var out [26]byte
	for i := 25; i >= 0; i-- {
		digit := new(big.Int).And(n, mask).Int64()
		out[i] = alphabet[digit]
		n.Rsh(n, 5)
	}
	return string(out[:])
}

type generator struct {
	mu          sync.Mutex
	ms          int64
	entropy     [10]byte
	initialized bool
}

var global generator

func (g *generator) new(kind Kind, now time.Time) string {
	if !known(kind) {
		panic("ids: unknown kind")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	ms := now.UnixMilli()
	if ms < 0 || ms > maxMillis {
		panic("ids: timestamp outside ULID range")
	}
	if !g.initialized || ms > g.ms {
		if _, err := rand.Read(g.entropy[:]); err != nil {
			panic(err)
		}
		g.ms, g.initialized = ms, true
	} else {
		overflow := true
		for i := len(g.entropy) - 1; i >= 0; i-- {
			g.entropy[i]++
			if g.entropy[i] != 0 {
				overflow = false
				break
			}
		}
		if overflow {
			if g.ms == maxMillis {
				panic("ids: ULID exhausted")
			}
			g.ms++
		}
	}
	return string(kind) + "_" + encode(g.ms, g.entropy)
}
func New(kind Kind) string { return global.new(kind, time.Now()) }
func Derive(kind Kind, at time.Time, seed string) string {
	if !known(kind) {
		panic("ids: unknown kind")
	}
	ms := at.UnixMilli()
	if ms < 0 || ms > maxMillis {
		panic("ids: timestamp outside ULID range")
	}
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + seed))
	var entropy [10]byte
	binary.BigEndian.PutUint16(entropy[:2], binary.BigEndian.Uint16(sum[:2]))
	copy(entropy[2:], sum[2:10])
	return string(kind) + "_" + encode(ms, entropy)
}
