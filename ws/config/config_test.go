package config

import "testing"

func TestValidateSuccess(t *testing.T) {
	cfg := DefaultConfiguration()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Configuration)
	}{
		{"empty address", func(c *Configuration) { c.ListenAddress = "" }},
		{"max connections", func(c *Configuration) { c.MaxConnections = 0 }},
		{"max per host", func(c *Configuration) { c.MaxConnectionsPerHost = 0 }},
		{"connect timeout", func(c *Configuration) { c.SSHConnectTimeout = 0 }},
		{"auth timeout", func(c *Configuration) { c.SSHAuthTimeout = 0 }},
		{"handshake timeout", func(c *Configuration) { c.SSHHandshakeTimeout = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfiguration()
			tt.modify(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}
