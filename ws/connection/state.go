package connection

import (
	"fmt"
	"sync/atomic"
)

// SessionState represents the current state of a bridge session
type SessionState int32

const (
	// StateCreated - Session has been created but not yet initialized
	StateCreated SessionState = iota
	// StateConnecting - SSH connection is being established
	StateConnecting
	// StateActive - Session is fully active and handling traffic
	StateActive
	// StateClosing - Session is being gracefully closed
	StateClosing
	// StateClosed - Session has been completely closed
	StateClosed
)

// String returns a human-readable representation of the session state
func (s SessionState) String() string {
	switch s {
	case StateCreated:
		return "CREATED"
	case StateConnecting:
		return "CONNECTING"
	case StateActive:
		return "ACTIVE"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// IsValidTransition checks if transitioning from current state to new state is valid
func (s SessionState) IsValidTransition(newState SessionState) bool {
	validTransitions := map[SessionState][]SessionState{
		StateCreated:    {StateConnecting, StateClosing},
		StateConnecting: {StateActive, StateClosing},
		StateActive:     {StateClosing},
		StateClosing:    {StateClosed},
		StateClosed:     {}, // No transitions from closed state
	}

	allowedStates, exists := validTransitions[s]
	if !exists {
		return false
	}

	for _, allowed := range allowedStates {
		if allowed == newState {
			return true
		}
	}
	return false
}

// SessionStateMachine manages atomic state transitions for a session
type SessionStateMachine struct {
	state int32 // Using int32 for atomic operations
}

// NewSessionStateMachine creates a new state machine initialized to StateCreated
func NewSessionStateMachine() *SessionStateMachine {
	return &SessionStateMachine{
		state: int32(StateCreated),
	}
}

// GetState returns the current state atomically
func (sm *SessionStateMachine) GetState() SessionState {
	return SessionState(atomic.LoadInt32(&sm.state))
}

// TransitionTo attempts to transition to a new state atomically
// Returns true if the transition was successful, false otherwise
func (sm *SessionStateMachine) TransitionTo(newState SessionState) bool {
	for {
		currentState := SessionState(atomic.LoadInt32(&sm.state))

		// Check if the transition is valid
		if !currentState.IsValidTransition(newState) {
			return false
		}

		// Attempt atomic compare-and-swap
		if atomic.CompareAndSwapInt32(&sm.state, int32(currentState), int32(newState)) {
			return true
		}

		// If CAS failed, another goroutine changed the state, retry
	}
}

// ForceTransitionTo unconditionally sets the state (use with caution)
func (sm *SessionStateMachine) ForceTransitionTo(newState SessionState) {
	atomic.StoreInt32(&sm.state, int32(newState))
}

// IsState checks if the current state matches the given state
func (sm *SessionStateMachine) IsState(state SessionState) bool {
	return sm.GetState() == state
}

// IsActive returns true if the session is in an active state
func (sm *SessionStateMachine) IsActive() bool {
	state := sm.GetState()
	return state == StateActive
}

// IsClosed returns true if the session is closed or closing
func (sm *SessionStateMachine) IsClosed() bool {
	state := sm.GetState()
	return state == StateClosing || state == StateClosed
}

// CanClose returns true if the session can transition to closing state
func (sm *SessionStateMachine) CanClose() bool {
	currentState := sm.GetState()
	return currentState.IsValidTransition(StateClosing)
}
