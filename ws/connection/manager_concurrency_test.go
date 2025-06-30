package connection

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/config"
)

// TestManagerConcurrentAccess tests concurrent access to manager
func TestManagerConcurrentAccess(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 5
	cfg.MaxConnectionsPerHost = 2

	manager := NewConnectionManager(cfg, nil)

	// Test concurrent access to host connection counting
	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			// Simulate checking limits
			for j := 0; j < 100; j++ {
				manager.GetHostConnectionCount("test-host")
				time.Sleep(time.Microsecond)
			}
		}()

		go func() {
			defer wg.Done()
			// Simulate updating host connections
			manager.hostMutex.Lock()
			manager.hostConnections["test-host"]++
			manager.hostMutex.Unlock()

			time.Sleep(time.Millisecond)

			manager.hostMutex.Lock()
			if manager.hostConnections["test-host"] > 0 {
				manager.hostConnections["test-host"]--
			}
			manager.hostMutex.Unlock()
		}()
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent access error: %v", err)
		}
	}
}

// TestParseTargetAddressMemoryLeak tests potential memory issues
func TestParseTargetAddressMemoryLeak(t *testing.T) {
	manager := &ConnectionManager{}

	// Test with many requests to see if there are memory leaks
	for i := 0; i < 10000; i++ {
		req := &http.Request{URL: &url.URL{Path: "/ws/host/22"}}
		_, err := manager.ParseTargetAddress(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestHostConnectionCounterInconsistency tests for counter inconsistencies
func TestHostConnectionCounterInconsistency(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 100
	cfg.MaxConnectionsPerHost = 50

	manager := NewConnectionManager(cfg, nil)

	// Simulate many concurrent connection attempts
	var wg sync.WaitGroup
	host := "test-host"

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Simulate connection setup
			manager.hostMutex.Lock()
			manager.hostConnections[host]++
			manager.hostMutex.Unlock()

			time.Sleep(time.Millisecond)

			// Simulate connection cleanup
			manager.hostMutex.Lock()
			if count := manager.hostConnections[host]; count > 0 {
				manager.hostConnections[host]--
				if manager.hostConnections[host] == 0 {
					delete(manager.hostConnections, host)
				}
			}
			manager.hostMutex.Unlock()
		}()
	}

	wg.Wait()

	// Check final state
	finalCount := manager.GetHostConnectionCount(host)
	if finalCount != 0 {
		t.Errorf("Expected host connection count to be 0, got %d", finalCount)
	}
}
