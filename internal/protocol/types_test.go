package protocol

import "testing"

func TestMaxMessageBytes(t *testing.T) {
	if MaxMessageBytes != 65536 {
		t.Errorf("MaxMessageBytes = %d, want 65536", MaxMessageBytes)
	}
}
