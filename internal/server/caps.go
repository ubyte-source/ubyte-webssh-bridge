package server

import (
	"sync"
	"sync/atomic"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// retiredSlot is the count of a slot that left the map: whoever loaded it loads again.
const retiredSlot = -1

// slot counts the sessions of one target.
type slot struct {
	n atomic.Int64
}

// caps bounds the concurrent sessions of the process and, on the path route, of each
// target, without a lock: perTarget holds a slot per target with a live session.
type caps struct {
	perTarget  sync.Map
	total      atomic.Int64
	maxTotal   int64
	maxPerHost int64
	pinned     bool
}

// newCaps returns the caps of c; with pinned, the cap of the process is the target's.
func newCaps(c *config.ConnConfig, pinned bool) *caps {
	return &caps{maxTotal: int64(c.MaxTotal), maxPerHost: int64(c.MaxPerHost), pinned: pinned}
}

// admit reserves a session to target and reports whether a cap left room for it.
func (c *caps) admit(target string) bool {
	if !c.reserve() {
		return false
	}
	if c.pinned {
		return true
	}
	for {
		s := c.slot(target)
		if retry, granted := c.acquire(s, s.n.Load()); !retry {
			if !granted {
				c.total.Add(-1)
			}
			return granted
		}
	}
}

// reserve takes one session of the process while it is under its cap.
func (c *caps) reserve() bool {
	for {
		n := c.total.Load()
		if n >= c.maxTotal {
			return false
		}
		if c.total.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// slot returns the slot of target: the one the map holds, else a new one it stores.
func (c *caps) slot(target string) *slot {
	fresh := new(slot)
	if loaded, found := c.perTarget.LoadOrStore(target, fresh); found {
		if s, ok := loaded.(*slot); ok {
			return s
		}
	}
	return fresh
}

// acquire takes one session of s, whose count its caller loaded as n: retry for a
// retired slot or a lost race, refused at the cap of a target.
func (c *caps) acquire(s *slot, n int64) (retry, granted bool) {
	switch {
	case n == retiredSlot:
		return true, false
	case n >= c.maxPerHost:
		return false, false
	}
	won := s.n.CompareAndSwap(n, n+1)
	return !won, won
}

// release gives back the session admit reserved for target; the last session of a
// target retires its slot.
func (c *caps) release(target string) {
	if !c.pinned {
		loaded, _ := c.perTarget.Load(target)
		if s, ok := loaded.(*slot); ok && s.n.Add(-1) == 0 && s.n.CompareAndSwap(0, retiredSlot) {
			c.perTarget.CompareAndDelete(target, s)
		}
	}
	c.total.Add(-1)
}
