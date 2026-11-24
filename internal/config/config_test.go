package config

import (
	"slices"
	"testing"
)

// TestConfigUnreadNamesReturnsACopy changes the names UnreadNames returned: the Config
// keeps its own.
func TestConfigUnreadNamesReturnsACopy(t *testing.T) {
	c := Config{unread: []string{"UWSB_A", "UWSB_B"}}
	names := c.UnreadNames()
	names[0] = "changed"
	if got, want := c.UnreadNames(), []string{"UWSB_A", "UWSB_B"}; !slices.Equal(got, want) {
		t.Errorf("UnreadNames() after a change of its result = %q, want %q", got, want)
	}
}
