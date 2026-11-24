package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/sshclient"
)

// The keepalive of the page and the bounds of the terminal bytes: a ping every
// pingInterval answered within pongTimeout, an output frame the page takes within
// outputTimeout, a write the shell takes within inputTimeout.
const (
	pingInterval  = 30 * time.Second
	pongTimeout   = 90 * time.Second
	outputTimeout = 90 * time.Second
	inputTimeout  = 5 * time.Minute
)

// closeAbnormal is the code of a session whose page is gone: no close frame is sent.
// closeTooBig is the code coder/websocket closes with on a message past the read limit.
const (
	closeAbnormal protocol.CloseCode = 1006
	closeTooBig                      = protocol.CloseCode(websocket.StatusMessageTooBig)
)

// readBuffer holds a message of the page and two bytes more: coder's read limit lets
// one byte past MaxMessageBytes through, and the read past it meets the limit.
const readBuffer = protocol.MaxMessageBytes + 2

// errPrefix starts the text of every error the package makes.
const errPrefix = "session: "

// The ends of a session that no other package names.
var (
	// errViolation reports a frame the session does not accept in its state.
	errViolation = errors.New(errPrefix + "protocol violation")
	// errPageGone reports a WebSocket that failed: the page is gone.
	errPageGone = errors.New(errPrefix + "page gone")
	// errPageSilent reports a page that answered no ping or took no output frame.
	errPageSilent = errors.New(errPrefix + "page stopped answering")
	// errStopped reports a session the server stops.
	errStopped = errors.New(errPrefix + "server shutting down")
	// errRefused reports a sign request the page refused.
	errRefused = errors.New(errPrefix + "signature refused by the page")
)

// exitError ends a session whose shell exited.
type exitError struct{ exit protocol.Exit }

// Error returns the end of the session.
func (exitError) Error() string { return errPrefix + "shell exited" }

// session is one page over one WebSocket and its SSH leg. The reader alone reads the
// WebSocket and forwards the terminal bytes; Run's goroutine runs the login, in which
// the Page methods take the page's answers from messages.
type session struct {
	start    time.Time
	conn     *websocket.Conn
	cfg      *config.Config
	log      *slog.Logger
	cancel   context.CancelCauseFunc
	client   *sshclient.Client
	shell    *sshclient.Shell
	connects chan protocol.Connect
	messages chan protocol.Message
	buf      []byte
	connect  protocol.Connect
	key      []byte
	id       string
	target   string
	peer     string
	addr     string
	user     string
	keyType  string
	keySHA   string
	size     protocol.Size
	signID   uint32
	// pending is the kind of the answer the page owes, 0 when it owes none.
	pending atomic.Uint32
	mu      sync.Mutex
	// active is set with ready; blocked while the reader waits on the shell; connected,
	// the reader's own, once the connect arrived.
	active    atomic.Bool
	blocked   atomic.Bool
	connected bool
}

// Run serves the page on conn for target, the client being client and the TCP peer
// being peer ("" when it is the client), until the session ends, and closes conn with
// the code that ended it; it returns after every goroutine it started has ended.
func Run(ctx context.Context, conn *websocket.Conn, cfg *config.Config, target, client, peer string, log *slog.Logger) {
	s, sctx, stop := newSession(ctx, conn, cfg, target, client, peer, log)
	defer stop()
	// page ends once the reader saw the WebSocket end, or at the stop.
	page, left := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		s.read(sctx)
		left()
	})
	wg.Go(func() { s.ping(sctx) })
	if err := s.serve(sctx, &wg); err != nil {
		s.cancel(err)
	}
	<-sctx.Done()
	s.finish(page, context.Cause(sctx), &wg)
}

// newSession returns the session of conn, its context, which ctx's end cancels with
// errStopped, and the function that releases the context.
func newSession(ctx context.Context, conn *websocket.Conn, cfg *config.Config, target, client, peer string,
	log *slog.Logger,
) (s *session, sctx context.Context, release func()) {
	sctx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() { cancel(errStopped) })
	s = &session{
		start: time.Now(), conn: conn, cfg: cfg, log: log, cancel: cancel,
		connects: make(chan protocol.Connect, 1), messages: make(chan protocol.Message),
		buf: make([]byte, readBuffer), id: rand.Text(), target: target, peer: peer, addr: client,
	}
	conn.SetReadLimit(protocol.MaxMessageBytes)
	log.LogAttrs(ctx, slog.LevelDebug, "session started", s.attrs(slog.String("target", target))...)
	return s, sctx, func() {
		stop()
		cancel(nil)
	}
}

// attrs returns the attributes of the session's records about its client, then more.
func (s *session) attrs(more ...slog.Attr) []slog.Attr {
	out := []slog.Attr{slog.String("session", s.id), slog.String("client", s.addr)}
	if s.peer != "" {
		out = append(out, slog.String("peer", s.peer))
	}
	return append(out, more...)
}

// serve runs the session from the connect message to the started shell, whose waiter
// it adds to wg, and returns the failure that ends the session early.
func (s *session) serve(ctx context.Context, wg *sync.WaitGroup) error {
	timer := time.NewTimer(s.cfg.WS.HandshakeTimeout)
	defer timer.Stop()
	select {
	case s.connect = <-s.connects:
	case <-timer.C:
		return errViolation
	case <-ctx.Done():
		return nil
	}
	s.user, s.key = s.connect.Login.User, s.connect.Login.Key
	client, err := sshclient.Dial(ctx, &s.cfg.SSH, s.target, s.connect.Login, s)
	s.connect = protocol.Connect{}
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	s.client = client
	s.authenticated(ctx)
	if err := s.open(ctx); err != nil {
		return err
	}
	wg.Go(func() {
		exit, err := s.shell.Wait()
		if err != nil {
			s.cancel(err)
			return
		}
		s.cancel(exitError{exit: exit})
	})
	s.active.Store(true)
	return s.write(ctx, websocket.MessageText, protocol.EncodeReady())
}

// authenticated writes the record of a login the device accepted.
func (s *session) authenticated(ctx context.Context) {
	attrs := s.attrs(slog.String("target", s.target), slog.String("user", s.user),
		slog.String("method", s.client.Method()))
	if key := s.loginKey(); key != "" {
		attrs = append(attrs, slog.String("key_sha256", key))
	}
	s.log.LogAttrs(ctx, slog.LevelInfo, "session authenticated", append(attrs, s.hostKeyAttrs()...)...)
}

// open opens and starts the shell at the size the page last sent, its output written
// within ctx, then gives it a size the page sent meanwhile; the lock stays free while
// the device answers, so the reader goes on reading the page.
func (s *session) open(ctx context.Context) error {
	s.mu.Lock()
	size := s.size
	s.mu.Unlock()
	shell, err := s.client.Open(ctx, size, &output{ctx: ctx, s: s})
	if err != nil {
		return fmt.Errorf("shell: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shell = shell
	if s.size != size {
		s.apply(ctx)
	}
	return nil
}

// read reads the page's frames until the WebSocket ends. It forwards the input, so a
// shell slow to take it slows the page down, and once the session ended drops them,
// cleared: the page's close frame comes behind its input, and Close waits 5s for it.
func (s *session) read(ctx context.Context) {
	for {
		typ, data, err := s.receive(ctx)
		if err != nil {
			s.cancel(err)
			return
		}
		if ctx.Err() != nil {
			clear(data)
			continue
		}
		if err := s.dispatch(ctx, typ, data); err != nil {
			s.cancel(err)
		}
	}
}

// receive reads one message of the page into the session's buffer; the read outlives
// the end of ctx, since closing the WebSocket ends it.
func (s *session) receive(ctx context.Context) (websocket.MessageType, []byte, error) {
	typ, r, err := s.conn.Reader(context.WithoutCancel(ctx))
	if err != nil {
		return 0, nil, errors.Join(errPageGone, err)
	}
	n, err := io.ReadFull(r, s.buf)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return typ, s.buf[:n], nil
	}
	return 0, nil, errors.Join(errPageGone, err)
}

// dispatch acts on one frame of the page in the session's state.
func (s *session) dispatch(ctx context.Context, typ websocket.MessageType, data []byte) error {
	if typ == websocket.MessageBinary {
		if !s.active.Load() {
			return errViolation
		}
		return s.forward(ctx, data)
	}
	m, err := protocol.Decode(data)
	clear(data)
	if err != nil {
		return fmt.Errorf("frame: %w", err)
	}
	if !s.accepts(m.Kind()) {
		return errViolation
	}
	switch m := m.(type) {
	case protocol.Connect:
		s.connected = true
		s.mu.Lock()
		s.size = m.Size
		s.mu.Unlock()
		s.connects <- m
	case protocol.Resize:
		s.resize(ctx, m.Size)
	default:
		select {
		case s.messages <- m:
		case <-ctx.Done():
		}
	}
	return nil
}

// accepts reports whether the session takes a message of kind k in its state: one
// connect first, then resizes, and the answer the page owes.
func (s *session) accepts(k protocol.Kind) bool {
	switch k {
	case protocol.KindConnect:
		return !s.connected
	case protocol.KindResize:
		return s.connected
	case protocol.KindRefusal:
		return s.pending.Load() == uint32(protocol.KindSignature)
	default:
		return s.pending.Load() == uint32(k)
	}
}

// resize records the size and applies it to the shell when there is one.
func (s *session) resize(ctx context.Context, size protocol.Size) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.size = size
	if s.shell != nil {
		s.apply(ctx)
	}
}

// apply gives the shell the size the page last sent, s.mu held; a failure, the
// device's, ends nothing, since the shell's Wait reports the end.
func (s *session) apply(ctx context.Context) {
	if err := s.shell.Resize(s.size); err != nil {
		s.log.LogAttrs(ctx, slog.LevelDebug, "resize failed", slog.String("session", s.id), slog.Any("error", err))
	}
}

// ping pings the page every pingInterval, skipping a round while the reader waits on
// the shell, and ends the session when no pong comes within pongTimeout.
func (s *session) ping(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if s.blocked.Load() {
			continue
		}
		if err := s.pong(ctx); err != nil {
			s.cancel(err)
			return
		}
	}
}

// pong pings the page and waits for its pong within pongTimeout, even past the end of
// ctx: coder/websocket closes the WebSocket on a write whose context ends.
func (s *session) pong(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pongTimeout)
	defer cancel()
	if err := s.conn.Ping(pctx); err != nil {
		return errors.Join(errPageSilent, err)
	}
	return nil
}

// write writes one frame to the page within outputTimeout, even past the end of ctx;
// a failure ends the session, as a page silent when the time ran out, else as a page
// gone.
func (s *session) write(ctx context.Context, typ websocket.MessageType, p []byte) error {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outputTimeout)
	defer cancel()
	err := s.conn.Write(wctx, typ, p)
	switch {
	case err == nil:
		return nil
	case wctx.Err() != nil:
		err = errors.Join(errPageSilent, err)
	default:
		err = errors.Join(errPageGone, err)
	}
	s.cancel(err)
	return err
}

// finish ends the SSH leg, writes the exit of a shell that ended and lets the page take
// it, closes the WebSocket with the code of cause, waits for the goroutines of wg and
// writes the session's last record.
func (s *session) finish(ctx context.Context, cause error, wg *sync.WaitGroup) {
	code := closeCode(cause)
	var exit exitError
	exited := errors.As(cause, &exit)
	if s.client != nil {
		cause = errors.Join(cause, s.client.Close())
	}
	if exited {
		cause = errors.Join(cause, s.write(ctx, websocket.MessageText, protocol.EncodeExit(exit.exit)),
			s.settle(ctx, wg))
	}
	if code == closeAbnormal {
		cause = errors.Join(cause, s.conn.CloseNow())
	} else {
		cause = errors.Join(cause, s.conn.Close(websocket.StatusCode(code), code.Reason()))
	}
	wg.Wait()
	attrs := []slog.Attr{slog.String("session", s.id), slog.Int("close_code", int(code))}
	if s.client != nil {
		attrs = append(attrs, slog.Duration("duration", time.Since(s.start)))
		if exit.exit.HasStatus {
			attrs = append(attrs, slog.Int("exit_status", exit.exit.Status))
		}
		s.log.LogAttrs(ctx, slog.LevelInfo, "session ended", attrs...)
		return
	}
	level := slog.LevelDebug
	if code == protocol.CloseUnreachable || code == protocol.CloseHandshakeFailed {
		level = slog.LevelWarn
	}
	attrs = s.attrs(slog.String("target", s.target), slog.Int("close_code", int(code)))
	attrs = append(append(attrs, s.hostKeyAttrs()...), slog.Any("error", cause))
	s.log.LogAttrs(ctx, level, "session failed", attrs...)
}

// settle pings the page behind the exit, in a goroutine of wg, and waits for the pong,
// which comes once the page took every frame before it, or for the end of ctx: the page
// gone or the stop. It returns the failure of the ping, none when ctx ended first.
func (s *session) settle(ctx context.Context, wg *sync.WaitGroup) error {
	ponged := make(chan error, 1)
	wg.Go(func() { ponged <- s.pong(ctx) })
	select {
	case err := <-ponged:
		return err
	case <-ctx.Done():
		return nil
	}
}

// closeCode returns the close code of the end of a session: closeTooBig for a message
// coder/websocket refused, closeAbnormal for any other page gone, to which no close
// frame goes.
func closeCode(err error) protocol.CloseCode {
	codes := [...]struct {
		err  error
		code protocol.CloseCode
	}{
		{websocket.ErrMessageTooBig, closeTooBig},
		{errPageGone, closeAbnormal},
		{errStopped, protocol.CloseGoingAway},
		{errPageSilent, protocol.ClosePageSilent},
		{errViolation, protocol.CloseViolation},
		{protocol.ErrInvalidMessage, protocol.CloseViolation},
		{sshclient.ErrInvalidKey, protocol.CloseViolation},
		{sshclient.ErrAuthFailed, protocol.CloseAuthFailed},
		{sshclient.ErrUnreachable, protocol.CloseUnreachable},
		{sshclient.ErrHandshake, protocol.CloseHandshakeFailed},
		{sshclient.ErrLoginTimeout, protocol.CloseLoginTimeout},
		{sshclient.ErrShellRefused, protocol.CloseShellRefused},
		{sshclient.ErrTargetLost, protocol.CloseTargetLost},
	}
	for _, c := range codes {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return protocol.CloseNormal
}
