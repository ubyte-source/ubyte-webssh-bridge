package config

import (
	"errors"
	"testing"
)

// TestProblemIsInvalidConfigAndItsRule builds a problem: it names the setting first,
// is ErrInvalidConfig and its rule, and unwraps to its cause.
func TestProblemIsInvalidConfigAndItsRule(t *testing.T) {
	err := newProblem("-rate-burst (UWSB_RATE_BURST)", errNotInteger)
	if got, want := err.Error(), "-rate-burst (UWSB_RATE_BURST): is not a base 10 integer"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	for target, want := range map[error]bool{ErrInvalidConfig: true, errNotInteger: true, ErrHelp: false} {
		if got := errors.Is(err, target); got != want {
			t.Errorf("errors.Is(%v, %v) = %v, want %v", err, target, got, want)
		}
	}
	if cause := errors.Unwrap(err); cause == nil || cause.Error() != err.Error() {
		t.Errorf("errors.Unwrap(%v) = %v, want the cause with the same text", err, cause)
	}
}
