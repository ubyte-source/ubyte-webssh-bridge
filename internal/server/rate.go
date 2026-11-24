package server

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// maxClients bounds the client addresses the limiter tracks, and retiredCell is the
// arrival time of a cell that left the map.
const (
	maxClients  = 65536
	retiredCell = -1
)

// ipv6KeyBits is the prefix of an IPv6 rate key: one host usually holds a whole /64.
const ipv6KeyBits = 64

// cell holds the theoretical arrival time of one rate key, in nanoseconds since the
// limiter's start.
type cell struct {
	key netip.Prefix
	tat atomic.Int64
}

// limiter is the GCRA bound on new sessions per rate key: burst at once, then one per
// emission; it tracks at most maxClients keys without a lock.
type limiter struct {
	start    time.Time
	cells    sync.Map
	count    atomic.Int64
	emission int64
	interval int64
	sweeping atomic.Bool
}

// newLimiter returns the limiter of r, its clock starting now.
func newLimiter(r *config.RateConfig) *limiter {
	return &limiter{start: time.Now(), emission: int64(r.Interval) / int64(r.Burst), interval: int64(r.Interval)}
}

// rateKey returns the rate key of addr: the address itself for IPv4, its /64 for IPv6.
func rateKey(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, min(addr.BitLen(), ipv6KeyBits)).Masked()
}

// admit reports whether key may open a new session now, and counts it.
func (l *limiter) admit(key netip.Prefix) bool {
	now := int64(time.Since(l.start))
	for {
		c := l.cell(key, now)
		if c == nil {
			return false
		}
		if retry, allowed := l.allow(c, c.tat.Load(), now); !retry {
			return allowed
		}
	}
}

// cell returns the cell of key, a full one made at now for a new key, or nil when the
// limiter holds no room for a new key.
func (l *limiter) cell(key netip.Prefix, now int64) *cell {
	loaded, _ := l.cells.Load(key)
	if c, ok := loaded.(*cell); ok {
		return c
	}
	if !l.room(now) {
		return nil
	}
	return l.store(key, now)
}

// store returns the cell of key, a full one made at now unless a racing caller stored
// one first, which gives the reservation of the count back.
func (l *limiter) store(key netip.Prefix, now int64) *cell {
	fresh := &cell{key: key}
	fresh.tat.Store(now)
	if loaded, found := l.cells.LoadOrStore(key, fresh); found {
		l.count.Add(-1)
		if known, ok := loaded.(*cell); ok {
			return known
		}
	}
	return fresh
}

// room reserves the count of one new key, sweeping the full cells once at the bound.
func (l *limiter) room(now int64) bool {
	if l.reserve() {
		return true
	}
	if l.sweeping.CompareAndSwap(false, true) {
		l.sweep(now)
		l.sweeping.Store(false)
	}
	return l.reserve()
}

// reserve takes one key of the count while it is under maxClients.
func (l *limiter) reserve() bool {
	for {
		n := l.count.Load()
		if n >= maxClients {
			return false
		}
		if l.count.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// sweep retires every cell that is full at now: one that no recent session drained.
func (l *limiter) sweep(now int64) {
	l.cells.Range(func(_, loaded any) bool {
		if c, ok := loaded.(*cell); ok {
			if tat := c.tat.Load(); tat <= now {
				l.retire(c, tat)
			}
		}
		return true
	})
}

// allow takes one session of c, whose arrival time its caller loaded as tat, at now:
// retry for a retired cell or a lost race, refused while the burst is spent.
func (l *limiter) allow(c *cell, tat, now int64) (retry, allowed bool) {
	if tat == retiredCell {
		return true, false
	}
	next := max(tat, now) + l.emission
	if next-now > l.interval {
		return false, false
	}
	won := c.tat.CompareAndSwap(tat, next)
	return !won, won
}

// retire takes c, whose arrival time its caller loaded as tat, out of the map unless
// a session changed it since.
func (l *limiter) retire(c *cell, tat int64) {
	if c.tat.CompareAndSwap(tat, retiredCell) {
		l.cells.CompareAndDelete(c.key, c)
		l.count.Add(-1)
	}
}
