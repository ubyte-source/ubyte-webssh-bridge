package ssh

import (
	"fmt"
	"time"
)

// SSHTimeouts encapsulates the various timeout settings for an SSH connection.
type SSHTimeouts struct {
	// ConnectTimeout is the maximum time to wait for the TCP connection to be established.
	ConnectTimeout time.Duration
	// AuthTimeout is the maximum time to wait for the SSH authentication to complete.
	AuthTimeout time.Duration
	// HandshakeTimeout is the maximum time for the entire SSH handshake process.
	HandshakeTimeout time.Duration
}

// DefaultSSHTimeouts provides a set of standard, sensible timeouts for SSH connections.
func DefaultSSHTimeouts() SSHTimeouts {
	return SSHTimeouts{
		ConnectTimeout:   10 * time.Second,
		AuthTimeout:      45 * time.Second,
		HandshakeTimeout: 60 * time.Second,
	}
}

// NewSSHTimeouts creates a new SSHTimeouts struct from the provided duration values.
func NewSSHTimeouts(connect, auth, handshake time.Duration) SSHTimeouts {
	return SSHTimeouts{
		ConnectTimeout:   connect,
		AuthTimeout:      auth,
		HandshakeTimeout: handshake,
	}
}

// Validate checks that the timeout values are valid and logically consistent.
func (t SSHTimeouts) Validate() error {
	if t.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be positive")
	}
	if t.AuthTimeout <= 0 {
		return fmt.Errorf("auth timeout must be positive")
	}
	if t.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be positive")
	}
	if t.HandshakeTimeout < t.AuthTimeout {
		return fmt.Errorf("handshake timeout must be greater than or equal to auth timeout")
	}
	return nil
}
