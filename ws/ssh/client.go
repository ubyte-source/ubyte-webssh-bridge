package ssh

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"golang.org/x/crypto/ssh"
)

// SSHClient provides a wrapper around the standard crypto/ssh client,
// adding timeout handling and a simplified interface.
type SSHClient struct {
	client    *ssh.Client
	config    *ssh.ClientConfig
	address   string
	logger    *logrus.Logger
	connected bool
}

// SSHSession represents an active SSH session, holding the session itself
// and its standard I/O pipes.
type SSHSession struct {
	session    *ssh.Session
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	client     *SSHClient
}

// NewSSHClient creates a new SSHClient with the specified credentials,
// address, timeouts, and logger.
func NewSSHClient(credentials message.Credentials, address string, timeouts SSHTimeouts, logger *logrus.Logger) *SSHClient {
	config := &ssh.ClientConfig{
		User:            credentials.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(credentials.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Not recommended for production
		Timeout:         timeouts.AuthTimeout,
		Config: ssh.Config{
			KeyExchanges: []string{
				// Modern algorithms (preferred)
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
				"diffie-hellman-group-exchange-sha256",
				// Legacy algorithms for maximum compatibility
				"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
				"diffie-hellman-group-exchange-sha1",
			},
			Ciphers: []string{
				// Modern ciphers (preferred)
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				// Legacy ciphers for maximum compatibility
				"aes128-cbc", "aes192-cbc", "aes256-cbc",
				"3des-cbc",
			},
			MACs: []string{
				// Modern MACs (preferred)
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512",
				// Legacy MACs for maximum compatibility
				"hmac-sha1", "hmac-sha1-96",
			},
		},
	}
	return &SSHClient{
		config:  config,
		address: address,
		logger:  logger,
	}
}

// Connect establishes a connection to the SSH server. It handles timeouts for
// the TCP connection, the SSH handshake, and authentication.
func (c *SSHClient) Connect(ctx context.Context, timeouts SSHTimeouts) error {
	if c.connected {
		return fmt.Errorf("SSH client is already connected")
	}

	c.logger.Infof("Attempting SSH connection to %s", c.address)

	connectCtx, cancel := context.WithTimeout(ctx, timeouts.HandshakeTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeouts.ConnectTimeout}
	conn, err := dialer.DialContext(connectCtx, "tcp", c.address)
	if err != nil {
		c.logger.Errorf("TCP connection to %s failed: %v", c.address, err)
		return fmt.Errorf("TCP connection failed: %v", err)
	}

	c.logger.Infof("TCP connection established, starting SSH handshake with %v timeout", timeouts.AuthTimeout)
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, c.address, c.config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			c.logger.Errorf("Failed to close connection after handshake failure: %v", closeErr)
		}
		c.logger.Errorf("SSH handshake to %s failed: %v", c.address, err)
		return fmt.Errorf("SSH handshake failed: %v", err)
	}

	c.logger.Infof("SSH connection successfully established to %s", c.address)
	c.client = ssh.NewClient(sshConn, chans, reqs)
	c.connected = true
	return nil
}

// NewSession creates a new interactive session on the connected SSH client.
// It requests a PTY and sets up the necessary I/O pipes.
func (c *SSHClient) NewSession() (*SSHSession, error) {
	if !c.connected || c.client == nil {
		return nil, fmt.Errorf("SSH client is not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %v", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 24, 80, modes); err != nil {
		if closeErr := session.Close(); closeErr != nil {
			c.logger.Errorf("Failed to close session after PTY request failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to request PTY: %v", err)
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		if closeErr := session.Close(); closeErr != nil {
			c.logger.Errorf("Failed to close session after stdin pipe failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to obtain stdin pipe: %v", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		if closeErr := session.Close(); closeErr != nil {
			c.logger.Errorf("Failed to close session after stdout pipe failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to obtain stdout pipe: %v", err)
	}
	session.Stderr = session.Stdout // Combine stderr with stdout

	return &SSHSession{
		session:    session,
		stdinPipe:  stdinPipe,
		stdoutPipe: stdoutPipe,
		client:     c,
	}, nil
}

// IsConnected returns true if the client is currently connected.
func (c *SSHClient) IsConnected() bool {
	return c.connected && c.client != nil
}

// Close terminates the SSH connection.
func (c *SSHClient) Close() error {
	if !c.IsConnected() {
		return nil
	}
	err := c.client.Close()
	c.connected = false
	c.client = nil
	return err
}

// GetAddress returns the address of the SSH server.
func (c *SSHClient) GetAddress() string {
	return c.address
}

// StartShell begins the shell on the remote server.
func (s *SSHSession) StartShell() error {
	return s.session.Shell()
}

// Wait blocks until the SSH session has finished.
func (s *SSHSession) Wait() error {
	return s.session.Wait()
}

// WindowChange sends a request to change the terminal window size.
func (s *SSHSession) WindowChange(rows, cols int) error {
	return s.session.WindowChange(rows, cols)
}

// GetStdinPipe returns the session's standard input pipe.
func (s *SSHSession) GetStdinPipe() io.WriteCloser {
	return s.stdinPipe
}

// GetStdoutPipe returns the session's standard output pipe.
func (s *SSHSession) GetStdoutPipe() io.Reader {
	return s.stdoutPipe
}

// GetSession returns the underlying crypto/ssh session.
func (s *SSHSession) GetSession() *ssh.Session {
	return s.session
}

// Close terminates the SSH session.
func (s *SSHSession) Close() error {
	return s.session.Close()
}
