package utils

import (
	"sync"
	"time"
)

// RateLimiter manages connection rate limiting
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

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(interval time.Duration, burst int, perIP bool, whitelist []string) *RateLimiter {
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelist {
		whitelistMap[ip] = true
	}

	rateLimiter := &RateLimiter{
		interval:        interval,
		burst:           burst,
		perIP:           perIP,
		whitelist:       whitelistMap,
		lastAttempts:    make(map[string]time.Time),
		attemptCounts:   make(map[string]int),
		cleanupInterval: interval * 2,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rateLimiter.cleanupExpiredEntries()

	return rateLimiter
}

// IsAllowed checks if a request from the given identifier is allowed
func (rateLimiter *RateLimiter) IsAllowed(identifier string) bool {
	// Check whitelist first
	if rateLimiter.whitelist[identifier] {
		return true
	}

	rateLimiter.mutex.Lock()
	defer rateLimiter.mutex.Unlock()

	now := time.Now()
	lastAttempt, exists := rateLimiter.lastAttempts[identifier]

	if !exists {
		// First attempt
		rateLimiter.lastAttempts[identifier] = now
		rateLimiter.attemptCounts[identifier] = 1
		return true
	}

	// Check if interval has passed
	if now.Sub(lastAttempt) > rateLimiter.interval {
		// Reset counter after interval
		rateLimiter.lastAttempts[identifier] = now
		rateLimiter.attemptCounts[identifier] = 1
		return true
	}

	// Within interval, check burst limit
	currentCount := rateLimiter.attemptCounts[identifier]
	if currentCount < rateLimiter.burst {
		rateLimiter.attemptCounts[identifier]++
		return true
	}

	// Rate limit exceeded
	return false
}

// RecordAttempt records an attempt for the given identifier
func (rateLimiter *RateLimiter) RecordAttempt(identifier string) {
	if rateLimiter.whitelist[identifier] {
		return
	}

	rateLimiter.mutex.Lock()
	defer rateLimiter.mutex.Unlock()

	now := time.Now()
	rateLimiter.lastAttempts[identifier] = now

	if count, exists := rateLimiter.attemptCounts[identifier]; exists {
		rateLimiter.attemptCounts[identifier] = count + 1
	} else {
		rateLimiter.attemptCounts[identifier] = 1
	}
}

// cleanupExpiredEntries removes old entries to prevent memory leaks
func (rateLimiter *RateLimiter) cleanupExpiredEntries() {
	ticker := time.NewTicker(rateLimiter.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rateLimiter.mutex.Lock()
			now := time.Now()
			cutoff := now.Add(-rateLimiter.interval * 2)

			for identifier, lastAttempt := range rateLimiter.lastAttempts {
				if lastAttempt.Before(cutoff) {
					delete(rateLimiter.lastAttempts, identifier)
					delete(rateLimiter.attemptCounts, identifier)
				}
			}
			rateLimiter.mutex.Unlock()

		case <-rateLimiter.stopCleanup:
			return
		}
	}
}

// Close stops the rate limiter and cleans up resources
func (rateLimiter *RateLimiter) Close() {
	close(rateLimiter.stopCleanup)
}

// GetStats returns current rate limiter statistics
func (rateLimiter *RateLimiter) GetStats() map[string]interface{} {
	rateLimiter.mutex.RLock()
	defer rateLimiter.mutex.RUnlock()

	return map[string]interface{}{
		"active_limiters": len(rateLimiter.lastAttempts),
		"interval":        rateLimiter.interval.String(),
		"burst":           rateLimiter.burst,
		"per_ip":          rateLimiter.perIP,
		"whitelist_size":  len(rateLimiter.whitelist),
	}
}
