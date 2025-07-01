package connection

import (
	"sync"
	"testing"
)

func TestSessionStateString(t *testing.T) {
	testCases := []struct {
		state    SessionState
		expected string
	}{
		{StateCreated, "CREATED"},
		{StateConnecting, "CONNECTING"},
		{StateActive, "ACTIVE"},
		{StateClosing, "CLOSING"},
		{StateClosed, "CLOSED"},
		{SessionState(999), "UNKNOWN(999)"},
	}

	for _, tc := range testCases {
		result := tc.state.String()
		if result != tc.expected {
			t.Errorf("State %d: expected %s, got %s", int(tc.state), tc.expected, result)
		}
	}
}

func TestSessionStateValidTransitions(t *testing.T) {
	validTransitions := map[SessionState][]SessionState{
		StateCreated:    {StateConnecting, StateClosing},
		StateConnecting: {StateActive, StateClosing},
		StateActive:     {StateClosing},
		StateClosing:    {StateClosed},
		StateClosed:     {},
	}

	for fromState, validToStates := range validTransitions {
		for _, toState := range validToStates {
			if !fromState.IsValidTransition(toState) {
				t.Errorf("Expected transition from %s to %s to be valid", fromState, toState)
			}
		}

		// Test invalid transitions
		allStates := []SessionState{StateCreated, StateConnecting, StateActive, StateClosing, StateClosed}
		for _, toState := range allStates {
			isValid := false
			for _, validState := range validToStates {
				if toState == validState {
					isValid = true
					break
				}
			}
			if !isValid && fromState.IsValidTransition(toState) {
				t.Errorf("Expected transition from %s to %s to be invalid", fromState, toState)
			}
		}
	}
}

func TestSessionStateMachineBasicOperations(t *testing.T) {
	sm := NewSessionStateMachine()

	// Initial state should be Created
	if sm.GetState() != StateCreated {
		t.Errorf("Expected initial state to be CREATED, got %s", sm.GetState())
	}

	// Test valid transition
	if !sm.TransitionTo(StateConnecting) {
		t.Error("Expected transition from CREATED to CONNECTING to succeed")
	}

	if sm.GetState() != StateConnecting {
		t.Errorf("Expected state to be CONNECTING, got %s", sm.GetState())
	}

	// Test invalid transition
	if sm.TransitionTo(StateCreated) {
		t.Error("Expected transition from CONNECTING to CREATED to fail")
	}

	// State should remain unchanged after invalid transition
	if sm.GetState() != StateConnecting {
		t.Errorf("Expected state to remain CONNECTING, got %s", sm.GetState())
	}
}

func TestSessionStateMachineHelperMethods(t *testing.T) {
	sm := NewSessionStateMachine()

	// Test IsState
	if !sm.IsState(StateCreated) {
		t.Error("Expected IsState(CREATED) to be true initially")
	}

	if sm.IsState(StateActive) {
		t.Error("Expected IsState(ACTIVE) to be false initially")
	}

	// Test IsActive
	if sm.IsActive() {
		t.Error("Expected IsActive() to be false initially")
	}

	// Transition to active
	sm.TransitionTo(StateConnecting)
	sm.TransitionTo(StateActive)

	if !sm.IsActive() {
		t.Error("Expected IsActive() to be true when state is ACTIVE")
	}

	// Test IsClosed
	if sm.IsClosed() {
		t.Error("Expected IsClosed() to be false when state is ACTIVE")
	}

	// Transition to closing
	sm.TransitionTo(StateClosing)

	if !sm.IsClosed() {
		t.Error("Expected IsClosed() to be true when state is CLOSING")
	}

	if sm.IsActive() {
		t.Error("Expected IsActive() to be false when state is CLOSING")
	}

	// Test CanClose
	sm.ForceTransitionTo(StateActive)
	if !sm.CanClose() {
		t.Error("Expected CanClose() to be true when state is ACTIVE")
	}

	sm.ForceTransitionTo(StateClosed)
	if sm.CanClose() {
		t.Error("Expected CanClose() to be false when state is CLOSED")
	}
}

func TestSessionStateMachineForceTransition(t *testing.T) {
	sm := NewSessionStateMachine()

	// Force transition to any state should work
	sm.ForceTransitionTo(StateClosed)
	if sm.GetState() != StateClosed {
		t.Errorf("Expected forced transition to CLOSED to work, got %s", sm.GetState())
	}

	// Force transition from closed to active (normally invalid)
	sm.ForceTransitionTo(StateActive)
	if sm.GetState() != StateActive {
		t.Errorf("Expected forced transition to ACTIVE to work, got %s", sm.GetState())
	}
}

func TestSessionStateMachineConcurrency(t *testing.T) {
	sm := NewSessionStateMachine()
	const numGoroutines = 100

	var wg sync.WaitGroup
	successCount := make(chan bool, numGoroutines)

	// Start many goroutines trying to transition simultaneously
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success := sm.TransitionTo(StateConnecting)
			successCount <- success
		}()
	}

	wg.Wait()
	close(successCount)

	// Count successful transitions
	successes := 0
	for success := range successCount {
		if success {
			successes++
		}
	}

	// Only one transition should succeed due to atomic operations
	if successes != 1 {
		t.Errorf("Expected exactly 1 successful transition, got %d", successes)
	}

	// Final state should be CONNECTING
	if sm.GetState() != StateConnecting {
		t.Errorf("Expected final state to be CONNECTING, got %s", sm.GetState())
	}
}

func TestSessionStateMachineStateProgression(t *testing.T) {
	sm := NewSessionStateMachine()

	// Test complete lifecycle
	states := []SessionState{StateConnecting, StateActive, StateClosing, StateClosed}

	for _, expectedState := range states {
		if !sm.TransitionTo(expectedState) {
			t.Errorf("Failed to transition to %s", expectedState)
		}
		if sm.GetState() != expectedState {
			t.Errorf("Expected state %s, got %s", expectedState, sm.GetState())
		}
	}

	// After reaching CLOSED, no further transitions should be possible
	if sm.TransitionTo(StateActive) {
		t.Error("Expected transition from CLOSED to ACTIVE to fail")
	}
}
