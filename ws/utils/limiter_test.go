package utils

import (
	"testing"
	"time"
)

func TestRateLimiterBasic(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 2, true, nil)
	id := "1.2.3.4"
	if !rl.IsAllowed(id) || !rl.IsAllowed(id) {
		t.Fatal("first two attempts should be allowed")
	}
	if rl.IsAllowed(id) {
		t.Fatal("third attempt should be blocked")
	}
	time.Sleep(120 * time.Millisecond)
	if !rl.IsAllowed(id) {
		t.Fatal("should be allowed after interval")
	}
	rl.Close()
}

func TestRateLimiterWhitelist(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 1, true, []string{"whitelisted"})
	if !rl.IsAllowed("whitelisted") {
		t.Fatal("whitelisted identifier should always be allowed")
	}
	rl.Close()
}
