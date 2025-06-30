package ssh

import (
	"fmt"
	"time"
)

// SSHTimeouts holds various timeout configurations for SSH connections
type SSHTimeouts struct {
	// ConnectTimeout defines the timeout for establishing TCP connection to SSH server
	ConnectTimeout time.Duration
	// AuthTimeout defines the timeout for SSH authentication (including RADIUS)
	AuthTimeout time.Duration
	// HandshakeTimeout defines the total timeout for SSH handshake
	HandshakeTimeout time.Duration
}

// DefaultSSHTimeouts returns default SSH timeout values optimized for RADIUS authentication
func DefaultSSHTimeouts() SSHTimeouts {
	return SSHTimeouts{
		ConnectTimeout:   10 * time.Second,
		AuthTimeout:      45 * time.Second,
		HandshakeTimeout: 60 * time.Second,
	}
}

// NewSSHTimeouts creates SSH timeouts from individual duration values
func NewSSHTimeouts(connectTimeout, authTimeout, handshakeTimeout time.Duration) SSHTimeouts {
	return SSHTimeouts{
		ConnectTimeout:   connectTimeout,
		AuthTimeout:      authTimeout,
		HandshakeTimeout: handshakeTimeout,
	}
}

// Validate checks if the timeout values are reasonable
func (timeouts SSHTimeouts) Validate() error {
	if timeouts.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be positive")
	}
	if timeouts.AuthTimeout <= 0 {
		return fmt.Errorf("auth timeout must be positive")
	}
	if timeouts.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be positive")
	}
	if timeouts.HandshakeTimeout < timeouts.AuthTimeout {
		return fmt.Errorf("handshake timeout should be greater than or equal to auth timeout")
	}
	return nil
}
