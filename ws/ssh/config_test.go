package ssh

import "testing"

func TestSSHTimeoutsValidate(t *testing.T) {
	touts := DefaultSSHTimeouts()
	if err := touts.Validate(); err != nil {
		t.Fatalf("expected valid defaults, got %v", err)
	}
}

func TestSSHTimeoutsValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*SSHTimeouts)
	}{
		{"connect", func(s *SSHTimeouts) { s.ConnectTimeout = 0 }},
		{"auth", func(s *SSHTimeouts) { s.AuthTimeout = 0 }},
		{"handshake", func(s *SSHTimeouts) { s.HandshakeTimeout = 0 }},
		{"handshake<auth", func(s *SSHTimeouts) { s.HandshakeTimeout = s.AuthTimeout - 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := DefaultSSHTimeouts()
			tt.mod(&s)
			if err := s.Validate(); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}
