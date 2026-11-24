package server

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// testRate is the rate of the limiter tests: 10 at once, then one per 200 ms.
func testRate() *config.RateConfig {
	return &config.RateConfig{Burst: 10, Interval: 2 * time.Second}
}

// keyOf returns the rate key of the address s.
func keyOf(s string) netip.Prefix {
	return rateKey(netip.MustParseAddr(s))
}

// TestLimiterAdmitGrantsTheBurstThenOnePerEmission admits one key: Burst at once, the
// next refused, one more after an emission, and the whole burst after the interval.
func TestLimiterAdmitGrantsTheBurstThenOnePerEmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, k := newLimiter(testRate()), keyOf("203.0.113.7")
		for i := range 10 {
			if !l.admit(k) {
				t.Fatalf("admission %d of the burst refused, want it granted", i+1)
			}
		}
		if l.admit(k) {
			t.Fatal("admission 11 granted, want the burst spent")
		}
		time.Sleep(200 * time.Millisecond)
		if !l.admit(k) || l.admit(k) {
			t.Fatal("after one emission: want one admission, then a refusal")
		}
		time.Sleep(2 * time.Second)
		granted := 0
		for range 11 {
			if l.admit(k) {
				granted++
			}
		}
		if granted != 10 {
			t.Errorf("after the interval: %d admissions, want the burst of 10", granted)
		}
	})
}

// TestRateKeyGroupsAnIPv6Slash64 keys addresses: two IPv6 addresses of one /64 share a
// key, of two /64s do not, an IPv4 address is its own key.
func TestRateKeyGroupsAnIPv6Slash64(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"2001:db8:1:2::7", "2001:db8:1:2:ffff::1", true},
		{"2001:db8:1:2::7", "2001:db8:1:3::7", false},
		{"192.0.2.1", "192.0.2.2", false},
	} {
		if got := keyOf(tc.a) == keyOf(tc.b); got != tc.same {
			t.Errorf("rateKey(%s) == rateKey(%s) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		l := newLimiter(&config.RateConfig{Burst: 1, Interval: time.Second})
		first, same, other := keyOf("2001:db8:1:2::7"), keyOf("2001:db8:1:2::8"), keyOf("2001:db8:1:3::7")
		if !l.admit(first) || l.admit(same) || !l.admit(other) {
			t.Error("a /64 shares one burst, another /64 has its own: want granted, refused, granted")
		}
	})
}

// fill admits 65536 distinct keys of l, the bound of the keys it tracks.
func fill(t *testing.T, l *limiter) {
	t.Helper()
	for i := range 65536 {
		addr := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if !l.admit(rateKey(addr)) {
			t.Fatalf("admission of key %d refused, want it granted", i)
		}
	}
}

// TestLimiterAdmitRefusesANewKeyPastTheBound fills the limiter: a new key is refused
// while every cell has a session, a known key keeps working.
func TestLimiterAdmitRefusesANewKeyPastTheBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newLimiter(testRate())
		fill(t, l)
		if l.admit(keyOf("203.0.113.7")) {
			t.Error("a new key past the bound granted, want it refused")
		}
		if !l.admit(keyOf("198.18.0.1")) {
			t.Error("a known key past the bound refused, want it granted")
		}
	})
}

// TestLimiterAdmitSweepsTheFullCells fills the limiter and waits the interval: a new
// key sweeps every full cell and passes.
func TestLimiterAdmitSweepsTheFullCells(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newLimiter(testRate())
		fill(t, l)
		time.Sleep(2 * time.Second)
		if !l.admit(keyOf("203.0.113.7")) {
			t.Fatal("a new key after the cells filled up refused, want them swept")
		}
		if got := l.count.Load(); got != 1 {
			t.Errorf("count after the sweep = %d, want the new key alone", got)
		}
	})
}

// TestLimiterAllowOnAStaleLoad calls allow with the loads a racing caller sees: a
// retired cell and a lost CAS retry.
func TestLimiterAllowOnAStaleLoad(t *testing.T) {
	l := newLimiter(&config.RateConfig{Burst: 2, Interval: time.Second})
	c := &cell{key: keyOf("203.0.113.7")}
	c.tat.Store(retiredCell)
	if retry, allowed := l.allow(c, retiredCell, 0); !retry || allowed {
		t.Errorf("allow(retired) = %v, %v, want a retry", retry, allowed)
	}
	c.tat.Store(int64(time.Second))
	if retry, allowed := l.allow(c, 0, 0); !retry || allowed || c.tat.Load() != int64(time.Second) {
		t.Errorf("allow(stale 0) = %v, %v, tat %d, want a retry and the tat kept", retry, allowed, c.tat.Load())
	}
}

// TestLimiterAllowOnACurrentLoad calls allow with the arrival time the cell holds: a
// spent burst refuses, a free one grants and moves the time on by one emission.
func TestLimiterAllowOnACurrentLoad(t *testing.T) {
	l := newLimiter(&config.RateConfig{Burst: 2, Interval: time.Second})
	c := &cell{key: keyOf("203.0.113.7")}
	c.tat.Store(int64(time.Second))
	if retry, allowed := l.allow(c, int64(time.Second), 0); retry || allowed {
		t.Errorf("allow(a spent burst) = %v, %v, want refused", retry, allowed)
	}
	c.tat.Store(0)
	if retry, allowed := l.allow(c, 0, 0); retry || !allowed || c.tat.Load() != int64(time.Second/2) {
		t.Errorf("allow(0) = %v, %v, tat %d, want granted and one emission", retry, allowed, c.tat.Load())
	}
	c.tat.Store(1)
	if retry, allowed := l.allow(c, 1, 1); retry || !allowed {
		t.Errorf("allow(1) = %v, %v, want an arrival time of 1 ns granted", retry, allowed)
	}
}

// TestLimiterAllowAtTheInterval calls allow where the next arrival time lands at the
// interval, which grants, and 1 ns past it, which refuses.
func TestLimiterAllowAtTheInterval(t *testing.T) {
	l := newLimiter(&config.RateConfig{Burst: 2, Interval: time.Second})
	for _, tc := range []struct {
		tat     int64
		allowed bool
	}{{int64(time.Second / 2), true}, {int64(time.Second/2) + 1, false}} {
		c := &cell{key: keyOf("203.0.113.7")}
		c.tat.Store(tc.tat)
		if retry, allowed := l.allow(c, tc.tat, 0); retry || allowed != tc.allowed {
			t.Errorf("allow(%d) = %v, %v, want no retry and allowed %v", tc.tat, retry, allowed, tc.allowed)
		}
	}
}

// TestLimiterSweepRetiresTheFullCells sweeps at 5 ns: the cell full at 5 ns leaves the
// map and the count, the one full at 6 ns stays.
func TestLimiterSweepRetiresTheFullCells(t *testing.T) {
	l := newLimiter(testRate())
	full, busy := keyOf("203.0.113.7"), keyOf("203.0.113.8")
	for range 2 {
		if !l.reserve() {
			t.Fatal("reserve() = false, want room")
		}
	}
	l.store(full, 5)
	l.store(busy, 6)
	l.sweep(5)
	_, fullHeld := l.cells.Load(full)
	_, busyHeld := l.cells.Load(busy)
	if fullHeld || !busyHeld || l.count.Load() != 1 {
		t.Errorf("sweep(5) left full %v, busy %v, count %d, want the full cell alone retired", fullHeld, busyHeld,
			l.count.Load())
	}
}

// TestLimiterRetireOnAStaleLoad retires a cell with a stale arrival time: a session
// changed it, so it stays; with the current one it leaves the map and the count.
func TestLimiterRetireOnAStaleLoad(t *testing.T) {
	l := newLimiter(testRate())
	k := keyOf("203.0.113.7")
	if !l.reserve() {
		t.Fatal("reserve() = false, want room")
	}
	c := l.store(k, 5)
	l.retire(c, 4)
	if loaded, held := l.cells.Load(k); !held || loaded != c || c.tat.Load() != 5 || l.count.Load() != 1 {
		t.Errorf("retire(stale) left held %v, tat %d, count %d, want the cell kept", held, c.tat.Load(),
			l.count.Load())
	}
	l.retire(c, 5)
	if _, held := l.cells.Load(k); held || c.tat.Load() != retiredCell || l.count.Load() != 0 {
		t.Errorf("retire(current) left held %v, tat %d, count %d, want it retired", held, c.tat.Load(),
			l.count.Load())
	}
}

// TestLimiterStoreKeepsAKnownCell stores a key another caller stored first: the
// known cell comes back and the count gives back its reservation.
func TestLimiterStoreKeepsAKnownCell(t *testing.T) {
	l := newLimiter(testRate())
	k := keyOf("203.0.113.7")
	for range 2 {
		if !l.reserve() {
			t.Fatal("reserve() = false, want room")
		}
	}
	first := l.store(k, 5)
	if got := l.store(k, 9); got != first || got.tat.Load() != 5 || l.count.Load() != 1 {
		t.Errorf("store(known) = tat %d, count %d, want the first cell and a count of 1", got.tat.Load(),
			l.count.Load())
	}
}

// TestLimiterAdmitUnderConcurrentCallers runs callers of one key at once, 1000 times:
// the burst is granted exactly.
func TestLimiterAdmitUnderConcurrentCallers(t *testing.T) {
	for range 1000 {
		synctest.Test(t, func(t *testing.T) {
			l, k := newLimiter(&config.RateConfig{Burst: 4, Interval: time.Second}), keyOf("203.0.113.7")
			var granted atomic.Int64
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if l.admit(k) {
						granted.Add(1)
					}
				})
			}
			wg.Wait()
			if got := granted.Load(); got != 4 {
				t.Fatalf("8 callers at once granted %d, want the burst of 4", got)
			}
		})
	}
}
