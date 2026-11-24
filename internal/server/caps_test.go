package server

import (
	"strconv"
	"sync"
	"testing"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// TestCapsAdmitStopsAtMaxTotal admits sessions to distinct targets on the path route:
// MaxTotal pass, the next is refused, and a release frees its place.
func TestCapsAdmitStopsAtMaxTotal(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 3, MaxPerHost: 3}, false)
	for i := range 3 {
		if !c.admit("192.0.2." + strconv.Itoa(i) + ":22") {
			t.Fatalf("admission %d of 3 refused, want it granted", i+1)
		}
	}
	if c.admit("198.51.100.1:22") {
		t.Error("admission 4 of MaxTotal 3 granted, want it refused")
	}
	c.release("192.0.2.0:22")
	if !c.admit("198.51.100.1:22") {
		t.Error("admission after a release refused, want it granted")
	}
	if got := c.total.Load(); got != 3 {
		t.Errorf("total = %d, want 3", got)
	}
}

// TestCapsAdmitStopsAtMaxPerHost admits sessions to one target on the path route:
// MaxPerHost pass, the next is refused while another target passes, and the refusal
// gives its reservation of the total back.
func TestCapsAdmitStopsAtMaxPerHost(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 10, MaxPerHost: 2}, false)
	if got := admits(c, 3); got != 2 {
		t.Errorf("3 admissions to one target granted %d, want MaxPerHost 2", got)
	}
	if !c.admit("device.example.test:22") {
		t.Error("admission to another target refused, want it granted")
	}
	if got := c.total.Load(); got != 3 {
		t.Errorf("total = %d, want 3: the refusal gives its reservation back", got)
	}
}

// TestCapsAdmitCountsAPinnedTargetAgainstMaxTotal admits sessions to the pinned target:
// MaxTotal pass whatever MaxPerHost holds, and no slot is kept.
func TestCapsAdmitCountsAPinnedTargetAgainstMaxTotal(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 3, MaxPerHost: 1}, true)
	if got := admits(c, 4); got != 3 {
		t.Errorf("4 admissions to the pinned target granted %d, want MaxTotal 3", got)
	}
	c.release(testTarget)
	if got := admits(c, 2); got != 1 {
		t.Errorf("admissions after a release granted %d, want 1", got)
	}
	c.perTarget.Range(func(key, _ any) bool {
		t.Errorf("perTarget holds %v, want no slot for a pinned target", key)
		return true
	})
}

// TestCapsReleaseRetiresTheLastSlot releases every session of a target: its slot
// leaves the map retired, and the target admits again.
func TestCapsReleaseRetiresTheLastSlot(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 10, MaxPerHost: 2}, false)
	admits(c, 2)
	loaded, _ := c.perTarget.Load(testTarget)
	s, ok := loaded.(*slot)
	if !ok {
		t.Fatalf("perTarget holds %v, want the slot of %s", loaded, testTarget)
	}
	c.release(testTarget)
	c.release(testTarget)
	if _, held := c.perTarget.Load(testTarget); held || s.n.Load() != retiredSlot || c.total.Load() != 0 {
		t.Errorf("after the last release: held %v, slot %d, total %d, want no slot, retired, 0", held, s.n.Load(),
			c.total.Load())
	}
	if !c.admit(testTarget) {
		t.Error("admission after the slot retired refused, want a new slot")
	}
}

// TestCapsAcquireOnAStaleLoad calls acquire with the loads a racing caller sees: a
// retired slot and a lost CAS retry.
func TestCapsAcquireOnAStaleLoad(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 10, MaxPerHost: 2}, false)
	s := new(slot)
	s.n.Store(retiredSlot)
	if retry, granted := c.acquire(s, retiredSlot); !retry || granted {
		t.Errorf("acquire(retired) = %v, %v, want a retry", retry, granted)
	}
	s.n.Store(1)
	if retry, granted := c.acquire(s, 0); !retry || granted || s.n.Load() != 1 {
		t.Errorf("acquire(stale 0 of 1) = %v, %v, count %d, want a retry and 1 kept", retry, granted, s.n.Load())
	}
}

// TestCapsAcquireOnACurrentLoad calls acquire with the count the slot holds: the cap
// refuses, under it the count grows.
func TestCapsAcquireOnACurrentLoad(t *testing.T) {
	c := newCaps(&config.ConnConfig{MaxTotal: 10, MaxPerHost: 2}, false)
	s := new(slot)
	s.n.Store(2)
	if retry, granted := c.acquire(s, 2); retry || granted {
		t.Errorf("acquire(2 of cap 2) = %v, %v, want refused", retry, granted)
	}
	s.n.Store(1)
	if retry, granted := c.acquire(s, 1); retry || !granted || s.n.Load() != 2 {
		t.Errorf("acquire(1) = %v, %v, count %d, want granted and 2", retry, granted, s.n.Load())
	}
}

// TestCapsAdmitUnderConcurrentCallers runs callers that admit and release two targets
// at once, 1000 times: the caps hold at every grant and end empty.
func TestCapsAdmitUnderConcurrentCallers(t *testing.T) {
	const callers, perHost = 8, 3
	for range 1000 {
		c := newCaps(&config.ConnConfig{MaxTotal: 5, MaxPerHost: perHost}, false)
		var held [2]int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range callers {
			target := []string{testTarget, "device.example.test:22"}[i%2]
			wg.Go(func() {
				if !c.admit(target) {
					return
				}
				mu.Lock()
				held[i%2]++
				over := held[i%2] > perHost || held[0]+held[1] > 5
				mu.Unlock()
				if over {
					t.Errorf("held %v past the caps", held)
				}
				mu.Lock()
				held[i%2]--
				mu.Unlock()
				c.release(target)
			})
		}
		wg.Wait()
		if c.total.Load() != 0 {
			t.Fatalf("total after every release = %d, want 0", c.total.Load())
		}
		c.perTarget.Range(func(key, _ any) bool {
			t.Fatalf("perTarget holds %v after every release, want none", key)
			return true
		})
	}
}
