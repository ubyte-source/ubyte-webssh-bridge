package connection

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/config"
)

// TestManagerConcurrentAccess tests concurrent access to manager using channel-based operations
func TestManagerConcurrentAccess(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 5
	cfg.MaxConnectionsPerHost = 2

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	// Test concurrent access to host connection counting
	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			// Simulate checking limits through channel operations
			for j := 0; j < 100; j++ {
				manager.GetHostConnectionCount("test-host")
				time.Sleep(time.Microsecond)
			}
		}()

		go func(index int) {
			defer wg.Done()
			// Simulate updating host connections through channel operations
			sessionID := fmt.Sprintf("test-session-%d", index)

			// Add session (increments host connection)
			response := manager.executeOperation(OpAddSession, map[string]interface{}{
				"sessionID":     sessionID,
				"session":       &BridgeSession{ID: sessionID, TargetAddress: "test-host"},
				"targetAddress": "test-host",
			})

			if !response.Success && response.Error != nil {
				select {
				case errors <- response.Error:
				default:
				}
			}

			time.Sleep(time.Millisecond)

			// Remove session (decrements host connection)
			response = manager.executeOperation(OpRemoveSession, sessionID)
			if !response.Success && response.Error != nil {
				select {
				case errors <- response.Error:
				default:
				}
			}
		}(i)
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
	cfg := config.DefaultConfiguration()
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	// Test with many requests to see if there are memory leaks
	for i := 0; i < 10000; i++ {
		req := &http.Request{URL: &url.URL{Path: "/ws/host/22"}}
		_, err := manager.ParseTargetAddress(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestHostConnectionCounterInconsistency tests for counter inconsistencies using channel operations
func TestHostConnectionCounterInconsistency(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 100
	cfg.MaxConnectionsPerHost = 50

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	// Simulate many concurrent connection attempts
	var wg sync.WaitGroup
	host := "test-host"

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("consistency-test-session-%d", index)

			// Simulate connection setup through channel operation
			response := manager.executeOperation(OpAddSession, map[string]interface{}{
				"sessionID":     sessionID,
				"session":       &BridgeSession{ID: sessionID, TargetAddress: host},
				"targetAddress": host,
			})

			if response.Success {
				time.Sleep(time.Millisecond)

				// Simulate connection cleanup through channel operation
				manager.executeOperation(OpRemoveSession, sessionID)
			}
		}(i)
	}

	wg.Wait()

	// Check final state
	finalCount := manager.GetHostConnectionCount(host)
	if finalCount != 0 {
		t.Errorf("Expected host connection count to be 0, got %d", finalCount)
	}
}

// TestChannelBasedConcurrency tests the channel-based approach under high concurrency
func TestChannelBasedConcurrency(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 100
	cfg.MaxConnectionsPerHost = 20

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	var wg sync.WaitGroup
	numGoroutines := 50
	operationsPerGoroutine := 20

	// Test concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				sessionID := fmt.Sprintf("concurrent-session-%d-%d", goroutineID, j)
				host := fmt.Sprintf("host-%d.example.com:22", j%5) // 5 different hosts

				// Check limits
				response := manager.executeOperation(OpCheckLimits, map[string]interface{}{
					"targetAddress": host,
				})

				if response.Success {
					// Add session
					response = manager.executeOperation(OpAddSession, map[string]interface{}{
						"sessionID":     sessionID,
						"session":       &BridgeSession{ID: sessionID, TargetAddress: host},
						"targetAddress": host,
					})

					if response.Success {
						// Get stats
						manager.executeOperation(OpGetStats, nil)

						// Update stats
						manager.executeOperation(OpUpdateStats, map[string]interface{}{
							"successful": true,
						})

						// Remove session
						manager.executeOperation(OpRemoveSession, sessionID)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	stats := manager.GetStats()
	activeSessions := stats["active_sessions"].(int)

	if activeSessions != 0 {
		t.Errorf("Expected 0 active sessions after test, got %d", activeSessions)
	}

	// Verify total sessions tracked correctly
	totalSessions := stats["total_sessions"].(int64)
	if totalSessions == 0 {
		t.Error("Expected some total sessions to be tracked")
	}

	t.Logf("Test completed: %d total sessions processed", totalSessions)
}

// TestChannelBufferSaturation tests behavior when channels become full
func TestChannelBufferSaturation(t *testing.T) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 10
	cfg.MaxConnectionsPerHost = 5

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	// Attempt to saturate the operation channel
	var wg sync.WaitGroup
	errors := make(chan error, 200)

	// Send many operations rapidly
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			response := manager.executeOperation(OpGetStats, nil)
			if !response.Success {
				select {
				case errors <- fmt.Errorf("operation %d failed: %v", index, response.Error):
				default:
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for timeouts or failures
	errorCount := 0
	for err := range errors {
		errorCount++
		if errorCount < 5 { // Log first few errors
			t.Logf("Channel saturation error: %v", err)
		}
	}

	// Some operations might timeout under extreme load, but most should succeed
	if errorCount > 100 { // Allow some failures under extreme load
		t.Errorf("Too many operations failed (%d/200), channel-based system may be overwhelmed", errorCount)
	}
}

// BenchmarkChannelBasedOperations benchmarks the channel-based approach
func BenchmarkChannelBasedOperations(b *testing.B) {
	cfg := config.DefaultConfiguration()
	cfg.MaxConnections = 1000
	cfg.MaxConnectionsPerHost = 100

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	manager := NewConnectionManager(cfg, logger)
	defer manager.executeOperation(OpShutdown, nil)

	b.ResetTimer()

	b.Run("GetStats", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			manager.executeOperation(OpGetStats, nil)
		}
	})

	b.Run("CheckLimits", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			manager.executeOperation(OpCheckLimits, map[string]interface{}{
				"targetAddress": "benchmark-host:22",
			})
		}
	})

	b.Run("AddRemoveSession", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sessionID := fmt.Sprintf("benchmark-session-%d", i)

			// Add session
			response := manager.executeOperation(OpAddSession, map[string]interface{}{
				"sessionID":     sessionID,
				"session":       &BridgeSession{ID: sessionID, TargetAddress: "benchmark-host:22"},
				"targetAddress": "benchmark-host:22",
			})

			if response.Success {
				// Remove session
				manager.executeOperation(OpRemoveSession, sessionID)
			}
		}
	})
}
