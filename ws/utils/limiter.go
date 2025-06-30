package utils

import (
	"sync"
	"time"
)

// RateLimiter provides a simple, token bucket-based rate limiting mechanism.
type RateLimiter struct {
	interval        time.Duration
	burst           int
	perIP           bool
	whitelist       map[string]bool
	lastAttempts    map[string]time.Time
	attemptCounts   map[string]int
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewRateLimiter creates and starts a new RateLimiter.
func NewRateLimiter(interval time.Duration, burst int, perIP bool, whitelist []string) *RateLimiter {
	wlMap := make(map[string]bool)
	for _, ip := range whitelist {
		wlMap[ip] = true
	}

	limiter := &RateLimiter{
		interval:        interval,
		burst:           burst,
		perIP:           perIP,
		whitelist:       wlMap,
		lastAttempts:    make(map[string]time.Time),
		attemptCounts:   make(map[string]int),
		cleanupInterval: interval * 2,
		stopCleanup:     make(chan struct{}),
	}
	go limiter.cleanupExpiredEntries()
	return limiter
}

// IsAllowed determines if a request from a given identifier should be allowed
// based on the rate limiting rules.
func (rl *RateLimiter) IsAllowed(identifier string) bool {
	if rl.whitelist[identifier] {
		return true
	}

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	last, exists := rl.lastAttempts[identifier]

	if !exists || now.Sub(last) > rl.interval {
		rl.lastAttempts[identifier] = now
		rl.attemptCounts[identifier] = 1
		return true
	}

	if rl.attemptCounts[identifier] < rl.burst {
		rl.attemptCounts[identifier]++
		return true
	}

	return false
}

// RecordAttempt manually records a connection attempt for a given identifier.
func (rl *RateLimiter) RecordAttempt(identifier string) {
	if rl.whitelist[identifier] {
		return
	}

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.lastAttempts[identifier] = time.Now()
	rl.attemptCounts[identifier]++
}

// cleanupExpiredEntries is a background task that periodically removes old
// entries from the rate limiter to prevent memory growth.
func (rl *RateLimiter) cleanupExpiredEntries() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mutex.Lock()
			cutoff := time.Now().Add(-rl.interval * 2)
			for id, last := range rl.lastAttempts {
				if last.Before(cutoff) {
					delete(rl.lastAttempts, id)
					delete(rl.attemptCounts, id)
				}
			}
			rl.mutex.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Close stops the background cleanup goroutine.
func (rl *RateLimiter) Close() {
	close(rl.stopCleanup)
}

// GetStats returns a map of the rate limiter's current statistics.
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	return map[string]interface{}{
		"active_limiters": len(rl.lastAttempts),
		"interval":        rl.interval.String(),
		"burst":           rl.burst,
		"per_ip":          rl.perIP,
		"whitelist_size":  len(rl.whitelist),
	}
}
