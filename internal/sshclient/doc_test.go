package sshclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// The login every test types.
const (
	testUser     = "user01"
	testPassword = "secret01"
	testTarget   = "192.0.2.10:22"
)

// pipeChunks is the room of each direction of a pipe, in writes.
const pipeChunks = 1 << 12

// memAddr is the address of a memConn.
type memAddr struct{}

// Network returns "mem".
func (memAddr) Network() string { return "mem" }

// String returns "mem".
func (memAddr) String() string { return "mem" }

// pipeEnd is the end of both directions of a pipe: done closes once, and reads then
// return err.
type pipeEnd struct {
	done chan struct{}
	err  error
	once sync.Once
}

// close ends both directions, reads returning err from then on; an end closed already
// returns io.ErrClosedPipe.
func (e *pipeEnd) close(err error) error {
	closed := io.ErrClosedPipe
	e.once.Do(func() {
		e.err = err
		close(e.done)
		closed = nil
	})
	return closed
}

// memConn is one end of an in-memory connection whose writes wait for room, never for
// the reader, as a TCP connection's buffer: x/crypto writes its version before reading
// the other's, which net.Pipe would deadlock.
type memConn struct {
	in, out chan []byte
	end     *pipeEnd
	rest    []byte
	// frozen drops what this end writes: the other end, a device whose SSH stack
	// stopped, takes nothing and answers nothing.
	frozen atomic.Bool
}

// pipe returns the two ends of an in-memory connection.
func pipe() (client, server *memConn) {
	toServer, toClient := make(chan []byte, pipeChunks), make(chan []byte, pipeChunks)
	end := &pipeEnd{done: make(chan struct{})}
	return &memConn{in: toClient, out: toServer, end: end}, &memConn{in: toServer, out: toClient, end: end}
}

// Read reads what the other end wrote, then the error of the end once either end
// closed.
func (c *memConn) Read(p []byte) (int, error) {
	if len(c.rest) == 0 {
		select {
		case c.rest = <-c.in:
		default:
			select {
			case c.rest = <-c.in:
			case <-c.end.done:
				return 0, c.end.err
			}
		}
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write queues a copy of p for the other end, or drops it once the end is frozen.
func (c *memConn) Write(p []byte) (int, error) {
	if c.frozen.Load() {
		return len(p), nil
	}
	select {
	case <-c.end.done:
		return 0, net.ErrClosed
	case c.out <- bytes.Clone(p):
		return len(p), nil
	}
}

// Close closes both ends, reads then returning io.EOF; a connection closed already
// returns io.ErrClosedPipe.
func (c *memConn) Close() error {
	return c.end.close(io.EOF)
}

// LocalAddr returns a placeholder address.
func (*memConn) LocalAddr() net.Addr { return memAddr{} }

// RemoteAddr returns a placeholder address.
func (*memConn) RemoteAddr() net.Addr { return memAddr{} }

// SetDeadline does nothing: the tests bound their waits by contexts.
func (*memConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline does nothing.
func (*memConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline does nothing.
func (*memConn) SetWriteDeadline(time.Time) error { return nil }

// newHostKey returns a generated Ed25519 host key of a device.
func newHostKey(tb testing.TB) ssh.Signer {
	tb.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		tb.Fatalf("host signer: %v", err)
	}
	return signer
}

// shellRequest is a channel request the device's session received.
type shellRequest struct {
	kind    string
	payload []byte
}

// device is the in-process SSH server of the tests: config logs users in, refuse
// names the session requests it refuses and ignore those it never answers, and run
// plays the shell on its channel.
type device struct {
	tb       testing.TB
	config   *ssh.ServerConfig
	run      func(ch ssh.Channel)
	requests chan shellRequest
	refuse   []string
	ignore   []string
	conns    []net.Conn
	mu       sync.Mutex
	wg       sync.WaitGroup
}

// newDevice returns a device with a host key, accepting user01 with testPassword; the
// test sets the shell it runs.
func newDevice(tb testing.TB) *device {
	tb.Helper()
	d := &device{tb: tb, requests: make(chan shellRequest, 64)}
	d.config = &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == testUser && string(password) == testPassword {
				return &ssh.Permissions{}, nil
			}
			return nil, errRefusedByDevice
		},
	}
	d.config.AddHostKey(newHostKey(tb))
	return d
}

// The failures of the device, the page and the user in the tests.
var (
	errRefusedByDevice = errors.New("refused by the device")
	errRefusedByPage   = errors.New("refused by the page")
	errPageGone        = errors.New("page gone")
)

// readError returns the error of a read of a TCP connection that met errno, as package
// net reports it.
func readError(errno syscall.Errno) error {
	return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)}
}

// note logs err, which a device meets when its peer leaves first.
func (d *device) note(err error) {
	if err != nil {
		d.tb.Logf("device: %v", err)
	}
}

// serve serves conn until the connection ends; the test waits for it with stop.
func (d *device) serve(conn net.Conn) {
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	d.wg.Go(func() {
		sc, chans, reqs, err := ssh.NewServerConn(conn, d.config)
		if err != nil {
			d.note(errors.Join(err, conn.Close()))
			return
		}
		d.wg.Go(func() { ssh.DiscardRequests(reqs) })
		for nc := range chans {
			if nc.ChannelType() != "session" || slices.Contains(d.refuse, "session") {
				d.note(nc.Reject(ssh.Prohibited, "no session"))
				continue
			}
			ch, chReqs, err := nc.Accept()
			if err != nil {
				d.note(err)
				continue
			}
			d.wg.Go(func() { d.session(ch, chReqs) })
		}
		d.note(sc.Close())
	})
}

// session answers the requests of one session channel and plays the shell once it is
// asked for.
func (d *device) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if slices.Contains(d.ignore, req.Type) {
			continue
		}
		ok := !slices.Contains(d.refuse, req.Type)
		d.requests <- shellRequest{kind: req.Type, payload: req.Payload}
		d.note(req.Reply(ok, nil))
		if ok && req.Type == "shell" {
			d.wg.Go(func() { d.run(ch) })
		}
	}
	d.note(ch.Close())
}

// cut closes every connection of the device, as a network that fails.
func (d *device) cut() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		d.note(c.Close())
	}
}

// stop waits for every goroutine of the device.
func (d *device) stop() {
	d.wg.Wait()
}

// listen serves the device on a loopback TCP listener until the test ends and
// returns its address.
func (d *device) listen(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.serve(conn)
		}
	}()
	t.Cleanup(func() {
		d.note(ln.Close())
		<-accepted
		d.stop()
	})
	return ln.Addr().String()
}

// exitWith returns a shell that sends the exit status and closes.
func (d *device) exitWith(status uint32) func(ch ssh.Channel) {
	return func(ch ssh.Channel) {
		_, err := ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
		d.note(errors.Join(err, ch.Close()))
	}
}

// testPage is the page of the tests: it signs with its keyring, answers challenges
// from answers in order and waits for ctx when none is left, shows banners at once or,
// with bannerWaits, waits for ctx, and records what it saw.
type testPage struct {
	keyring     agent.ExtendedAgent
	sign        func(ctx context.Context, data []byte, flags uint32) ([]byte, error)
	bannerErr   error
	answers     [][]string
	hostKeys    []string
	banners     []string
	challenges  []protocol.Challenge
	flags       []uint32
	mu          sync.Mutex
	bannerWaits bool
}

// newTestPage returns a page holding key in its keyring, when key is not nil, and
// answering with answers.
func newTestPage(tb testing.TB, key any, answers ...[]string) *testPage {
	tb.Helper()
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		tb.Fatal("the keyring is no ExtendedAgent")
	}
	p := &testPage{keyring: keyring, answers: answers}
	if key != nil {
		if err := p.keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
			tb.Fatalf("keyring: %v", err)
		}
	}
	return p
}

// HostKey records the host key.
func (p *testPage) HostKey(keyType, fingerprint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hostKeys = append(p.hostKeys, keyType+" "+fingerprint)
}

// Sign signs data with the keyring's key, or with sign when the test set one.
func (p *testPage) Sign(ctx context.Context, data []byte, flags uint32) ([]byte, error) {
	p.mu.Lock()
	p.flags = append(p.flags, flags)
	sign := p.sign
	p.mu.Unlock()
	if sign != nil {
		return sign(ctx, data, flags)
	}
	keys, err := p.keyring.List()
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	sig, err := p.keyring.SignWithFlags(keys[0], data, agent.SignatureFlags(flags))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return ssh.Marshal(sig), nil
}

// Answer returns the next scripted answers, or waits for the end of ctx.
func (p *testPage) Answer(ctx context.Context, c protocol.Challenge) ([]secret.Value, error) {
	p.mu.Lock()
	p.challenges = append(p.challenges, c)
	if len(p.answers) == 0 {
		p.mu.Unlock()
		<-ctx.Done()
		return nil, fmt.Errorf("no answer: %w", context.Cause(ctx))
	}
	next := p.answers[0]
	p.answers = p.answers[1:]
	p.mu.Unlock()
	values := make([]secret.Value, len(next))
	for i, a := range next {
		values[i] = secret.New(a)
	}
	return values, nil
}

// Banner records text, then waits for the end of ctx when bannerWaits is set, else
// fails with bannerErr when the test set one.
func (p *testPage) Banner(ctx context.Context, text string) error {
	p.mu.Lock()
	p.banners = append(p.banners, text)
	waits, err := p.bannerWaits, p.bannerErr
	p.mu.Unlock()
	if waits {
		<-ctx.Done()
		return fmt.Errorf("banner not shown: %w", context.Cause(ctx))
	}
	return err
}

// sshConfig returns the SSH settings of the tests.
func sshConfig() *config.SSHConfig {
	return &config.SSHConfig{ConnectTimeout: 10 * time.Second, LoginTimeout: 120 * time.Second}
}

// logInPipe logs in over an in-memory pipe to d as login says, page answering.
func logInPipe(t *testing.T, d *device, login *protocol.Login, page Page) (*Client, error) {
	t.Helper()
	client, server := pipe()
	d.serve(server)
	var key ssh.PublicKey
	if login.Key != nil {
		var err error
		if key, err = parseKey(login.Key); err != nil {
			t.Fatalf("parseKey: %v", err)
		}
	}
	c, err := logIn(t.Context(), client, sshConfig().LoginTimeout, testTarget, login, key, page)
	t.Cleanup(func() {
		if c != nil {
			d.note(c.Close())
		}
		d.stop()
	})
	return c, err
}

// passwordLogin returns the login of user01 with the typed password.
func passwordLogin() *protocol.Login {
	return &protocol.Login{User: testUser, Password: secret.New(testPassword)}
}

// newKey returns a private key of kind: ed25519, p256, p384, p521 or rsa.
func newKey(t *testing.T, kind string) any {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatalf("key %s: %v", kind, err)
	}
	return key
}

// publicBlob returns the SSH wire blob of the public key of key.
func publicBlob(t *testing.T, key any) []byte {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer.PublicKey().Marshal()
}

// switchingKey is a host key that presents first, and second from the key exchange
// that follows switchAt exchanges on.
type switchingKey struct {
	first, second ssh.Signer
	exchanges     atomic.Int32
	switchAt      atomic.Int32
}

// newSwitchingKey returns a switching key that switches after switchAt exchanges.
func newSwitchingKey(t *testing.T, switchAt int32) *switchingKey {
	t.Helper()
	k := &switchingKey{first: newHostKey(t), second: newHostKey(t)}
	k.switchAt.Store(switchAt)
	return k
}

// PublicKey returns the key of the exchange under way.
func (s *switchingKey) PublicKey() ssh.PublicKey {
	return s.current().PublicKey()
}

// Sign signs with the key of the exchange under way and counts the exchange.
func (s *switchingKey) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := s.current().Sign(r, data)
	s.exchanges.Add(1)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	return sig, nil
}

// current returns the key of the exchange under way.
func (s *switchingKey) current() ssh.Signer {
	if s.exchanges.Load() >= s.switchAt.Load() {
		return s.second
	}
	return s.first
}

// round is one keyboard-interactive round of a device and the answers it wants.
type round struct {
	name, instruction string
	questions         []string
	echos             []bool
	want              []string
}

// prompt returns a round of one question with its echo flag, wanting answer.
func prompt(question string, echo bool, answer string) round {
	return round{questions: []string{question}, echos: []bool{echo}, want: []string{answer}}
}

// interactive makes d log user01 in by keyboard-interactive through rounds, and by no
// other method.
func (d *device) interactive(rounds ...round) {
	d.config.PasswordCallback = nil
	d.config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (
		*ssh.Permissions, error,
	) {
		for _, r := range rounds {
			answers, err := client(r.name, r.instruction, r.questions, r.echos)
			if err != nil || !slices.Equal(answers, r.want) {
				return nil, errors.Join(errRefusedByDevice, err)
			}
		}
		return &ssh.Permissions{}, nil
	}
}

// openShell logs in to d with the typed password and opens a started shell.
func openShell(t *testing.T, d *device) *Shell {
	t.Helper()
	c, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
	if err != nil {
		t.Fatalf("logIn: %v", err)
	}
	shell, err := c.Open(t.Context(), protocol.Size{Cols: 80, Rows: 24}, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return shell
}

// waitFor returns the payload of the next session request of kind the device received.
func (d *device) waitFor(kind string) []byte {
	for r := range d.requests {
		if r.kind == kind {
			return r.payload
		}
	}
	return nil
}
