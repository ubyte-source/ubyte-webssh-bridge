package sshclient

import "errors"

// errPrefix starts the text of every error the package returns.
const errPrefix = "sshclient: "

// The failures of Dial, of a Client and of a Shell, each wrapped with its cause.
var (
	// ErrUnreachable reports a TCP connection to the target that fails or times out.
	ErrUnreachable = errors.New(errPrefix + "target unreachable")
	// ErrHandshake reports a version or key exchange that fails before the host key is
	// accepted, a close of the device included.
	ErrHandshake = errors.New(errPrefix + "SSH handshake failed")
	// ErrAuthFailed reports a login whose every method failed.
	ErrAuthFailed = errors.New(errPrefix + "authentication failed")
	// ErrLoginTimeout reports a login, or the opening of the shell after it, that
	// outlasted the login timeout.
	ErrLoginTimeout = errors.New(errPrefix + "login timed out")
	// ErrShellRefused reports a device that refused the session, the PTY or the shell.
	ErrShellRefused = errors.New(errPrefix + "shell refused")
	// ErrTargetLost reports a connection to the target that failed, other than by the
	// device's close or reset, without an exit status or signal or on a rekey that
	// presented another host key, or a shell that took no input in time.
	ErrTargetLost = errors.New(errPrefix + "connection to the target lost")
	// ErrInvalidKey reports a public key of the page that is no Ed25519, ECDSA or RSA
	// key of 1024 to 16384 bits.
	ErrInvalidKey = errors.New(errPrefix + "invalid public key")
)

// errHostKeyChanged reports a key exchange whose host key differs from the one the
// first exchange pinned.
var errHostKeyChanged = errors.New(errPrefix + "host key changed")
