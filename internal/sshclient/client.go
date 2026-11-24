package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// Page is the user behind the WebSocket: Sign, Answer and Banner wait for the page
// within ctx.
type Page interface {
	// HostKey takes the type and the SHA256 fingerprint of the host key of the first
	// key exchange, which reach only the session's records.
	HostKey(keyType, fingerprint string)
	// Sign returns the page's SSH wire signature of data for the agent flags.
	Sign(ctx context.Context, data []byte, flags uint32) ([]byte, error)
	// Answer returns the user's answers to c, one per prompt.
	Answer(ctx context.Context, c protocol.Challenge) ([]secret.Value, error)
	// Banner shows text, a banner of the device, to the user.
	Banner(ctx context.Context, text string) error
}

// The modulus sizes of an RSA key the page may announce.
const (
	minRSABits = 1024
	maxRSABits = 16384
)

// ttySpeed is the baud rate the PTY reports, which only old programs read.
const ttySpeed = 38400

// hostKeys accepts the host key of the first key exchange, pins it and tells the page,
// and refuses another key at every later exchange; x/crypto calls check on the one
// goroutine of its key exchanges.
type hostKeys struct {
	page    Page
	pinned  []byte
	seen    atomic.Bool
	changed atomic.Bool
}

// check is the host-key callback.
func (h *hostKeys) check(_ string, _ net.Addr, presented ssh.PublicKey) error {
	blob := presented.Marshal()
	if !h.seen.Load() {
		h.pinned = blob
		identity := presented
		if cert, ok := presented.(*ssh.Certificate); ok {
			identity = cert.Key
		}
		h.page.HostKey(identity.Type(), ssh.FingerprintSHA256(identity))
		h.seen.Store(true)
		return nil
	}
	if !slices.Equal(blob, h.pinned) {
		h.changed.Store(true)
		return errHostKeyChanged
	}
	return nil
}

// watchedConn is the connection to the target, which notes a read that fails other than
// at the device's close or reset of the connection: the connection is lost.
type watchedConn struct {
	net.Conn

	failed atomic.Bool
}

// Read reads from the connection.
func (w *watchedConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		w.failed.Store(true)
	}
	return n, err //nolint:wrapcheck // a Read returns the connection's own error: io.EOF stays io.EOF
}

// Client is an authenticated SSH connection to the target; its zero value is not
// ready: Dial builds it.
type Client struct {
	deadline time.Time // the end of the login, which bounds the opening of the shell too
	client   *ssh.Client
	conn     *watchedConn
	keys     *hostKeys
	method   string
}

// Dial connects to target and logs in as login says, with the signatures and answers
// of page, within the deadlines of cfg or until ctx ends.
func Dial(ctx context.Context, cfg *config.SSHConfig, target string, login protocol.Login, page Page) (*Client, error) {
	var key ssh.PublicKey
	if login.Key != nil {
		var err error
		if key, err = parseKey(login.Key); err != nil {
			return nil, err
		}
	}
	dialer := net.Dialer{Timeout: cfg.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Errorf("dial %s: %w", target, context.Cause(ctx))
	case err != nil:
		return nil, fmt.Errorf("dial %s: %w: %w", target, ErrUnreachable, err)
	}
	return logIn(ctx, conn, cfg.LoginTimeout, target, &login, key, page)
}

// rsaKey is the SSH wire form of an RSA public key.
type rsaKey struct {
	Type string
	E    *big.Int
	N    *big.Int
	Rest []byte `ssh:"rest"`
}

// parseKey returns the public key of blob, or ErrInvalidKey for a key that is no
// Ed25519, ECDSA or RSA key of minRSABits to maxRSABits bits.
func parseKey(blob []byte) (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return key, nil
	case ssh.KeyAlgoRSA:
		var k rsaKey
		if ssh.Unmarshal(blob, &k) == nil && k.N.BitLen() >= minRSABits && k.N.BitLen() <= maxRSABits {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: a %s key", ErrInvalidKey, key.Type())
}

// algorithms returns x/crypto's secure algorithms, then its insecure ones.
func algorithms() ssh.Algorithms {
	secure, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	return ssh.Algorithms{
		KeyExchanges: slices.Concat(secure.KeyExchanges, insecure.KeyExchanges),
		Ciphers:      slices.Concat(secure.Ciphers, insecure.Ciphers),
		MACs:         slices.Concat(secure.MACs, insecure.MACs),
		HostKeys:     slices.Concat(secure.HostKeys, insecure.HostKeys),
	}
}

// logIn runs the SSH handshake and the login over conn within timeout, the page
// answering for login, whose password it zeroes when the handshake returns.
func logIn(ctx context.Context, conn net.Conn, timeout time.Duration, target string, login *protocol.Login,
	key ssh.PublicKey, page Page,
) (*Client, error) {
	deadline := time.Now().Add(timeout)
	lctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	watched := &watchedConn{Conn: conn}
	guard := closeAtEnd(lctx, watched)
	p := &prompter{page: page, login: login, host: hostOf(target), method: methodNone}
	keys := &hostKeys{page: page}
	all := algorithms()
	cfg := &ssh.ClientConfig{
		KeyExchanges: all.KeyExchanges, Ciphers: all.Ciphers, MACs: all.MACs,
		User: login.User, Auth: p.methods(lctx, key), HostKeyCallback: keys.check,
		BannerCallback: p.banner(lctx), HostKeyAlgorithms: all.HostKeys,
	}
	c, chans, reqs, err := ssh.NewClientConn(watched, target, cfg)
	p.zero()
	if err = errors.Join(err, guard.done()); err != nil {
		return nil, fmt.Errorf("login %s: %w: %w", target, cause(ctx, lctx, keys, ErrAuthFailed), err)
	}
	return &Client{deadline: deadline, client: ssh.NewClient(c, chans, reqs), conn: watched, keys: keys,
		method: p.method}, nil
}

// closeGuard closes a connection once a context ends, until done.
type closeGuard struct {
	cancel func() bool
	err    chan error
}

// closeAtEnd closes c once ctx ends, which ends every wait on c, until done is called
// on what it returns.
func closeAtEnd(ctx context.Context, c io.Closer) closeGuard {
	ended := make(chan error, 1)
	return closeGuard{err: ended, cancel: context.AfterFunc(ctx, func() {
		ended <- errors.Join(context.Cause(ctx), c.Close())
	})}
}

// done cancels the close: it returns nil when the context had not ended, else the cause
// of the context joined with the error of the close.
func (g closeGuard) done() error {
	if g.cancel() {
		return nil
	}
	return <-g.err
}

// cause returns the class of the end of a login or of the opening of the shell: the
// end of ctx, the login timeout, a host key that changed, a handshake that never
// reached the host key, else failed, the class of the step.
func cause(ctx, lctx context.Context, keys *hostKeys, failed error) error {
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("ended: %w", context.Cause(ctx))
	case lctx.Err() != nil:
		return ErrLoginTimeout
	case keys.changed.Load():
		return ErrTargetLost
	case !keys.seen.Load():
		return ErrHandshake
	}
	return failed
}

// hostOf returns the host of target, host:port with an IPv6 host in brackets.
func hostOf(target string) string {
	return strings.Trim(target[:strings.LastIndexByte(target, ':')], "[]")
}

// Method returns the method that authenticated: publickey, keyboard-interactive or
// password.
func (c *Client) Method() string {
	return c.method
}

// Open opens a session with a PTY of size, whose output goes to out, and starts its
// shell before the login's deadline, or returns ErrShellRefused, ErrLoginTimeout or the
// end of ctx; the deadline or the end of ctx closes the connection.
func (c *Client) Open(ctx context.Context, size protocol.Size, out io.Writer) (*Shell, error) {
	octx, cancel := context.WithDeadline(ctx, c.deadline)
	defer cancel()
	guard := closeAtEnd(octx, c)
	shell, err := c.shell(size, out)
	if ended := guard.done(); err != nil || ended != nil {
		return nil, fmt.Errorf("open: %w: %w", cause(ctx, octx, c.keys, ErrShellRefused), errors.Join(err, ended))
	}
	return shell, nil
}

// Close closes the connection; a second call returns nil.
func (c *Client) Close() error {
	if err := c.client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// shell opens a session with a PTY of size, whose output goes to out, and starts its
// shell.
func (c *Client) shell(size protocol.Size, out io.Writer) (*Shell, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	session.Stdout, session.Stderr = out, out
	stdin, pipeErr := session.StdinPipe()
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.IUTF8: 1, ssh.TTY_OP_ISPEED: ttySpeed, ssh.TTY_OP_OSPEED: ttySpeed}
	if err := errors.Join(pipeErr, session.RequestPty("xterm", size.Rows, size.Cols, modes)); err != nil {
		return nil, fmt.Errorf("pty: %w", err)
	}
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("shell: %w", err)
	}
	return &Shell{session: session, stdin: stdin, client: c}, nil
}

// lost reports whether the connection failed or a key exchange presented another host
// key.
func (c *Client) lost() bool {
	return c.conn.failed.Load() || c.keys.changed.Load()
}
