package connection

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestBridgeSessionShutdownCoordination(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create a minimal session for testing shutdown coordination
	session := NewBridgeSession("test-session", nil, "localhost:22", "127.0.0.1", logger)

	// Test shutdown initiation
	if session.isShuttingDown() {
		t.Error("Session should not be shutting down initially")
	}

	session.initiateShutdown()

	if !session.isShuttingDown() {
		t.Error("Session should be shutting down after initiateShutdown()")
	}

	// Verify context is cancelled
	select {
	case <-session.Context.Done():
		// Good, context was cancelled
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after initiateShutdown()")
	}
}

func TestAcceptableCloseErrors(t *testing.T) {
	logger := logrus.New()

	// Create a minimal session for testing error handling
	session := NewBridgeSession("test-session", nil, "localhost:22", "127.0.0.1", logger)

	testCases := []struct {
		error      string
		acceptable bool
	}{
		{"use of closed network connection", true},
		{"broken pipe", true},
		{"connection reset by peer", true},
		{"websocket: close sent", true},
		{"EOF", true},
		{"some other error", false},
		{"", true}, // nil error
	}

	for _, tc := range testCases {
		var err error
		if tc.error != "" {
			err = &testError{tc.error}
		}

		result := session.isAcceptableCloseError(err)
		if result != tc.acceptable {
			t.Errorf("Error '%s': expected acceptable=%v, got %v", tc.error, tc.acceptable, result)
		}
	}
}

func TestStringContains(t *testing.T) {
	logger := logrus.New()

	session := &BridgeSession{
		Logger: logger,
	}

	testCases := []struct {
		str      string
		substr   string
		expected bool
	}{
		{"use of closed network connection", "closed", true},
		{"use of closed network connection", "use of closed", true},
		{"use of closed network connection", "open", false},
		{"", "", true},
		{"hello", "", true},
		{"", "hello", false},
		{"EOF", "EOF", true},
		{"websocket: close sent", "close", true},
	}

	for _, tc := range testCases {
		result := session.stringContains(tc.str, tc.substr)
		if result != tc.expected {
			t.Errorf("stringContains('%s', '%s'): expected %v, got %v", tc.str, tc.substr, tc.expected, result)
		}
	}
}

func TestCoordinatedCloseWithSyncOnce(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create a minimal session for testing coordinated close
	session := NewBridgeSession("test-session", nil, "localhost:22", "127.0.0.1", logger)

	// Set the session to active state to test transition
	session.stateMachine.TransitionTo(StateActive)

	// Test multiple close calls (simulate race condition)
	done := make(chan error, 3)
	closeCallCount := 0

	// Launch multiple goroutines trying to close the session
	for i := 0; i < 3; i++ {
		go func() {
			closeCallCount++
			done <- session.Close()
		}()
	}

	// Wait for all close operations to complete
	var errors []error
	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			errors = append(errors, err)
		}
	}

	// Verify that no errors occurred (all but first should be no-ops)
	if len(errors) > 0 {
		t.Errorf("Expected no errors from multiple close calls, got: %v", errors)
	}

	// Verify session is marked as inactive
	if session.IsActive() {
		t.Error("Expected session to be inactive after close")
	}

	// Verify shutdown flag is set
	if !session.isShuttingDown() {
		t.Error("Expected session to be shutting down after close")
	}
}

// Helper type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
