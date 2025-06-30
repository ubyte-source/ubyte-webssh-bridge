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
		{"negative max connections", func(c *Configuration) { c.MaxConnections = -1 }},
		{"zero max connections", func(c *Configuration) { c.MaxConnections = 0 }},
		{"negative max per host", func(c *Configuration) { c.MaxConnectionsPerHost = -1 }},
		{"zero max per host", func(c *Configuration) { c.MaxConnectionsPerHost = 0 }},
		{"negative connect timeout", func(c *Configuration) { c.SSHConnectTimeout = -1 }},
		{"zero connect timeout", func(c *Configuration) { c.SSHConnectTimeout = 0 }},
		{"negative auth timeout", func(c *Configuration) { c.SSHAuthTimeout = -1 }},
		{"zero auth timeout", func(c *Configuration) { c.SSHAuthTimeout = 0 }},
		{"negative handshake timeout", func(c *Configuration) { c.SSHHandshakeTimeout = -1 }},
		{"zero handshake timeout", func(c *Configuration) { c.SSHHandshakeTimeout = 0 }},
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

func TestValidateSpecificErrorMessages(t *testing.T) {
	tests := []struct {
		name          string
		modify        func(*Configuration)
		expectedError string
	}{
		{"empty address", func(c *Configuration) { c.ListenAddress = "" }, "listen address cannot be empty"},
		{"max connections", func(c *Configuration) { c.MaxConnections = 0 }, "max connections must be positive"},
		{"max per host", func(c *Configuration) { c.MaxConnectionsPerHost = 0 }, "max connections per host must be positive"},
		{"connect timeout", func(c *Configuration) { c.SSHConnectTimeout = 0 }, "SSH connect timeout must be positive"},
		{"auth timeout", func(c *Configuration) { c.SSHAuthTimeout = 0 }, "SSH auth timeout must be positive"},
		{"handshake timeout", func(c *Configuration) { c.SSHHandshakeTimeout = 0 }, "SSH handshake timeout must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfiguration()
			tt.modify(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if err.Error() != tt.expectedError {
				t.Fatalf("expected error message %q, got %q", tt.expectedError, err.Error())
			}
		})
	}
}
