package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// Shell is the shell of a session on a PTY; its zero value is not ready: Client.Open
// builds it.
type Shell struct {
	session *ssh.Session
	stdin   io.Writer
	client  *Client
}

// Write writes p to the shell's stdin, dropping it once the channel or the connection
// ended, which Wait reports, or returns ErrTargetLost when ctx ends first, which closes
// the connection: a device that takes no input leaves the write waiting until then.
func (s *Shell) Write(ctx context.Context, p []byte) error {
	guard := closeAtEnd(ctx, s.client)
	_, err := s.stdin.Write(p)
	if ended := guard.done(); ended != nil {
		return fmt.Errorf("write: %w: %w", ErrTargetLost, errors.Join(err, ended))
	}
	return nil
}

// Resize sets the size of the PTY, or returns ErrTargetLost.
func (s *Shell) Resize(size protocol.Size) error {
	if err := s.session.WindowChange(size.Rows, size.Cols); err != nil {
		return fmt.Errorf("resize: %w: %w", ErrTargetLost, err)
	}
	return nil
}

// Wait returns how the shell ended, or ErrTargetLost when it ended without an exit
// status or signal on a connection that failed or that a rekey ended: the device's
// close or reset of the connection is the end of its shell.
func (s *Shell) Wait() (protocol.Exit, error) {
	err := s.session.Wait()
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return protocol.Exit{HasStatus: true}, nil
	case errors.As(err, &exit):
		return protocol.Exit{Signal: exit.Signal(), Status: exit.ExitStatus(), HasStatus: true}, nil
	case errors.As(err, &missing) && !s.client.lost():
		return protocol.Exit{}, nil
	}
	return protocol.Exit{}, fmt.Errorf("wait: %w: %w", ErrTargetLost, err)
}
