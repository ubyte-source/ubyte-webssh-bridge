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

// SSHClient wraps ssh.Client with additional functionality
type SSHClient struct {
	client    *ssh.Client
	config    *ssh.ClientConfig
	address   string
	logger    *logrus.Logger
	connected bool
}

// SSHSession represents an SSH session with its I/O pipes
type SSHSession struct {
	session    *ssh.Session
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	client     *SSHClient
}

// NewSSHClient creates a new SSH client wrapper
func NewSSHClient(credentials message.Credentials, address string, timeouts SSHTimeouts, logger *logrus.Logger) *SSHClient {
	config := &ssh.ClientConfig{
		User:            credentials.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(credentials.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeouts.AuthTimeout,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group-exchange-sha1",
			},
			Ciphers: []string{
				"aes128-cbc",
				"aes192-cbc",
				"aes256-cbc",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"3des-cbc",
			},
		},
	}

	return &SSHClient{
		config:  config,
		address: address,
		logger:  logger,
	}
}

// Connect establishes the SSH connection with timeout handling
func (sshClient *SSHClient) Connect(ctx context.Context, timeouts SSHTimeouts) error {
	if sshClient.connected {
		return fmt.Errorf("SSH client is already connected")
	}

	if sshClient.logger != nil {
		sshClient.logger.Infof("Attempting SSH connection to %s with extended timeout for RADIUS auth", sshClient.address)
	}

	// Create context with timeout for the entire SSH handshake
	connectCtx, cancel := context.WithTimeout(ctx, timeouts.HandshakeTimeout)
	defer cancel()

	// Create custom dialer with connection timeout
	dialer := &net.Dialer{
		Timeout: timeouts.ConnectTimeout,
	}

	// Establish TCP connection with timeout
	conn, err := dialer.DialContext(connectCtx, "tcp", sshClient.address)
	if err != nil {
		if sshClient.logger != nil {
			sshClient.logger.Errorf("TCP connection failed to %s: %v", sshClient.address, err)
		}
		return fmt.Errorf("TCP connection failed: %v", err)
	}

	if sshClient.logger != nil {
		sshClient.logger.Infof("TCP connection established, starting SSH handshake with %v timeout", timeouts.AuthTimeout)
	}

	// Perform SSH handshake with the established connection
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, sshClient.address, sshClient.config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			if sshClient.logger != nil {
				sshClient.logger.Errorf("Failed to close connection: %v", closeErr)
			}
		}
		if sshClient.logger != nil {
			sshClient.logger.Errorf("SSH handshake failed to %s: %v", sshClient.address, err)
		}
		return fmt.Errorf("SSH handshake failed: %v", err)
	}

	if sshClient.logger != nil {
		sshClient.logger.Infof("SSH connection successfully established to %s", sshClient.address)
	}

	// Create SSH client from connection
	sshClient.client = ssh.NewClient(sshConn, chans, reqs)
	sshClient.connected = true

	return nil
}

// NewSession creates a new SSH session with PTY
func (sshClient *SSHClient) NewSession() (*SSHSession, error) {
	if !sshClient.connected || sshClient.client == nil {
		return nil, fmt.Errorf("SSH client is not connected")
	}

	session, err := sshClient.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %v", err)
	}

	// Request PTY with appropriate terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm", 24, 80, modes); err != nil {
		if closeErr := session.Close(); closeErr != nil {
			if sshClient.logger != nil {
				sshClient.logger.Errorf("Failed to close session after PTY request failure: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to request PTY: %v", err)
	}

	// Get stdin pipe
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		if closeErr := session.Close(); closeErr != nil {
			if sshClient.logger != nil {
				sshClient.logger.Errorf("Failed to close session after stdin pipe failure: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to obtain stdin pipe: %v", err)
	}

	// Get stdout pipe
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		if closeErr := session.Close(); closeErr != nil {
			if sshClient.logger != nil {
				sshClient.logger.Errorf("Failed to close session after stdout pipe failure: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to obtain stdout pipe: %v", err)
	}

	// Combine stderr with stdout
	session.Stderr = session.Stdout

	return &SSHSession{
		session:    session,
		stdinPipe:  stdinPipe,
		stdoutPipe: stdoutPipe,
		client:     sshClient,
	}, nil
}

// IsConnected returns whether the SSH client is connected
func (sshClient *SSHClient) IsConnected() bool {
	return sshClient.connected && sshClient.client != nil
}

// Close closes the SSH connection
func (sshClient *SSHClient) Close() error {
	if !sshClient.connected || sshClient.client == nil {
		return nil
	}

	err := sshClient.client.Close()
	sshClient.connected = false
	sshClient.client = nil

	return err
}

// GetAddress returns the SSH server address
func (sshClient *SSHClient) GetAddress() string {
	return sshClient.address
}

// StartShell starts the SSH shell session
func (sshSession *SSHSession) StartShell() error {
	return sshSession.session.Shell()
}

// Wait waits for the SSH session to complete
func (sshSession *SSHSession) Wait() error {
	return sshSession.session.Wait()
}

// WindowChange changes the terminal window size
func (sshSession *SSHSession) WindowChange(rows, cols int) error {
	return sshSession.session.WindowChange(rows, cols)
}

// GetStdinPipe returns the stdin pipe
func (sshSession *SSHSession) GetStdinPipe() io.WriteCloser {
	return sshSession.stdinPipe
}

// GetStdoutPipe returns the stdout pipe
func (sshSession *SSHSession) GetStdoutPipe() io.Reader {
	return sshSession.stdoutPipe
}

// GetSession returns the underlying SSH session
func (sshSession *SSHSession) GetSession() *ssh.Session {
	return sshSession.session
}

// Close closes the SSH session
func (sshSession *SSHSession) Close() error {
	return sshSession.session.Close()
}
