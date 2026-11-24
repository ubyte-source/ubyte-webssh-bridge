package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/coder/websocket"
	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/sshclient"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// allocRuns is how many runs an allocation count averages.
const allocRuns = 100

// raceEnabled reports whether the race detector is on, which allocates on its own.
func raceEnabled() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	return slices.Contains(info.Settings, debug.BuildSetting{Key: "-race", Value: strconv.FormatBool(true)})
}

// assertAllocs fails t unless f allocates want times per run; under the race detector
// it only runs f.
func assertAllocs(t *testing.T, want float64, f func()) {
	t.Helper()
	if raceEnabled() {
		f()
		return
	}
	if got := testing.AllocsPerRun(allocRuns, f); got != want {
		t.Errorf("allocs per run = %.0f, want %.0f", got, want)
	}
}

// The login every test types and the addresses it comes from.
const (
	testUser     = "user01"
	testPassword = "secret01"
	testClient   = "203.0.113.7"
	testPeer     = "127.0.0.1"
)

// errRefusedByDevice is the refusal of the device's callbacks.
var errRefusedByDevice = errors.New("refused by the device")

// hijacker is the ResponseWriter of the bridge's end of a pipe: its Hijack returns
// the end, as net/http's does for a WebSocket upgrade.
type hijacker struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	header http.Header
	err    error
}

// Header returns the response headers.
func (h *hijacker) Header() http.Header { return h.header }

// Write writes a response body, which an upgrade has none of.
func (h *hijacker) Write(p []byte) (int, error) {
	n, err := h.rw.Write(p)
	if err != nil {
		return n, fmt.Errorf("body: %w", err)
	}
	return n, nil
}

// WriteHeader writes the status line and the headers, as net/http writes a 101.
func (h *hijacker) WriteHeader(code int) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(code) + " " + http.StatusText(code) + "\r\n")
	h.err = h.header.Write(&b)
	b.WriteString("\r\n")
	_, err := io.WriteString(h.conn, b.String())
	h.err = errors.Join(h.err, err)
}

// Hijack returns the bridge's end, or the failure of the status line.
func (h *hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, h.err
}

// wsPair returns the bridge's and the page's ends of a WebSocket over net.Pipe, the
// page's through wrap.
func wsPair(ctx context.Context, tb testing.TB, wrap func(net.Conn) net.Conn) (bridge, page *websocket.Conn) {
	tb.Helper()
	bridgeEnd, pipeEnd := net.Pipe()
	pageEnd := wrap(pipeEnd)
	accepted := make(chan *websocket.Conn, 1)
	go func() {
		rw := bufio.NewReadWriter(bufio.NewReader(bridgeEnd), bufio.NewWriter(bridgeEnd))
		r, err := http.ReadRequest(rw.Reader)
		if err != nil {
			accepted <- nil
			return
		}
		conn, err := websocket.Accept(&hijacker{conn: bridgeEnd, rw: rw, header: http.Header{}}, r, nil)
		if err != nil {
			conn = nil
		}
		accepted <- conn
	}()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       func(context.Context, string, string) (net.Conn, error) { return pageEnd, nil },
	}
	page, resp, err := websocket.Dial(ctx, "ws://bridge.example.test/ws",
		&websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	if resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			tb.Fatal(err)
		}
	}
	bridge = <-accepted
	if bridge == nil {
		tb.Fatal("accept failed")
	}
	page.SetReadLimit(-1)
	return bridge, page
}

// drain reads the page's frames until the WebSocket ends and returns the bytes of
// the binary ones on the channel.
func drain(page *websocket.Conn) <-chan int {
	total := make(chan int, 1)
	go func() {
		n := 0
		for {
			typ, r, err := page.Reader(context.Background())
			if err != nil {
				total <- n
				return
			}
			m, err := io.Copy(io.Discard, r)
			if err != nil {
				total <- n
				return
			}
			if typ == websocket.MessageBinary {
				n += int(m)
			}
		}
	}()
	return total
}

// logBuffer is the record output of a session, safe for its goroutines.
type logBuffer struct {
	b  strings.Builder
	mu sync.Mutex
}

// Write appends p.
func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Write(p)
	return len(p), nil
}

// String returns the records written.
func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// records returns the records written, each decoded.
func (l *logBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(l.String()) {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// record returns the record of msg, failing t when there is none.
func (l *logBuffer) record(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, r := range l.records(t) {
		if r["msg"] == msg {
			return r
		}
	}
	t.Fatalf("no record %q in %s", msg, l.String())
	return nil
}

// testConfig returns the settings of the tests.
func testConfig() *config.Config {
	return &config.Config{
		SSH: config.SSHConfig{ConnectTimeout: 10 * time.Second, LoginTimeout: 120 * time.Second},
		WS:  config.WSConfig{HandshakeTimeout: 10 * time.Second},
	}
}

// run is one session under test: the page's end, the records and the end of Run.
type run struct {
	page *websocket.Conn
	logs *logBuffer
	done chan struct{}
}

// plain returns conn as it is.
func plain(conn net.Conn) net.Conn { return conn }

// mutedConn is the page's end of a pipe that drops every write once muted: a page
// that reads but answers nothing, not even a pong.
type mutedConn struct {
	net.Conn

	muted atomic.Bool
}

// Write writes p, or drops it once muted.
func (m *mutedConn) Write(p []byte) (int, error) {
	if m.muted.Load() {
		return len(p), nil
	}
	n, err := m.Conn.Write(p)
	if err != nil {
		return n, fmt.Errorf("page: %w", err)
	}
	return n, nil
}

// discardLogger returns a logger that writes nothing.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// closeStatus returns the WebSocket status of code.
func closeStatus(code protocol.CloseCode) websocket.StatusCode {
	return websocket.StatusCode(code)
}

// start runs a session to target with cfg, the client behind the loopback peer.
func start(ctx context.Context, t *testing.T, cfg *config.Config, target string) *run {
	t.Helper()
	return startWith(ctx, t, cfg, target, plain)
}

// startWith runs a session as start does, the page's end of the pipe through wrap.
func startWith(ctx context.Context, t *testing.T, cfg *config.Config, target string,
	wrap func(net.Conn) net.Conn,
) *run {
	t.Helper()
	bridge, page := wsPair(ctx, t, wrap)
	r := &run{page: page, logs: &logBuffer{}, done: make(chan struct{})}
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	go func() {
		defer close(r.done)
		Run(ctx, bridge, cfg, target, testClient, testPeer, log)
	}()
	t.Cleanup(func() {
		if err := page.CloseNow(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("page: %v", err)
		}
		<-r.done
	})
	return r
}

// send writes a text frame of the page.
func (r *run) send(t *testing.T, text string) {
	t.Helper()
	if err := r.page.Write(t.Context(), websocket.MessageText, []byte(text)); err != nil {
		t.Fatalf("page write: %v", err)
	}
}

// next reads the page's next frame.
func (r *run) next(t *testing.T) (typ websocket.MessageType, data []byte) {
	t.Helper()
	typ, data, err := r.page.Read(t.Context())
	if err != nil {
		t.Fatalf("page read: %v", err)
	}
	return typ, data
}

// expect reads text frames until one of type typ, or any when typ is "", which it
// returns decoded.
func (r *run) expect(t *testing.T, typ string) map[string]any {
	t.Helper()
	for {
		kind, data := r.next(t)
		if kind != websocket.MessageText {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("bridge frame %q: %v", data, err)
		}
		if typ == "" || m["type"] == typ {
			return m
		}
	}
}

// closed reads until the WebSocket closes and returns its close code.
func (r *run) closed(t *testing.T) websocket.StatusCode {
	t.Helper()
	for {
		_, _, err := r.page.Read(t.Context())
		if err != nil {
			<-r.done
			return websocket.CloseStatus(err)
		}
	}
}

// connectFrame returns the connect message of user01 with the extra members.
func connectFrame(extra string) string {
	return `{"type":"connect","user":"user01"` + extra + `,"cols":80,"rows":24}`
}

// device is the SSH server of the session tests on a loopback listener: it logs user01
// in and plays shell on each session; it refuses the session request refuse, and keeps
// its answer to held until answer, telling asked when held came.
type device struct {
	tb       testing.TB
	refuse   string
	held     string
	asked    chan struct{}
	release  chan struct{}
	config   *ssh.ServerConfig
	shell    func(ch ssh.Channel)
	resized  chan [2]uint32
	conns    []*net.TCPConn
	answered sync.Once
	mu       sync.Mutex
	wg       sync.WaitGroup
	// frozen stops the device's SSH stack: it takes the bridge's bytes and answers
	// nothing.
	frozen atomic.Bool
}

// newDevice returns a device whose shell is shell.
func newDevice(tb testing.TB, shell func(d *device, ch ssh.Channel)) *device {
	tb.Helper()
	d := &device{tb: tb, asked: make(chan struct{}, 1), release: make(chan struct{}), resized: make(chan [2]uint32, 16)}
	d.shell = func(ch ssh.Channel) { shell(d, ch) }
	d.config = &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == testUser && string(password) == testPassword {
				return &ssh.Permissions{}, nil
			}
			return nil, errRefusedByDevice
		},
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		tb.Fatal(err)
	}
	d.config.AddHostKey(signer)
	return d
}

// note logs err, which a device meets when its peer leaves first.
func (d *device) note(err error) {
	if err != nil {
		d.tb.Logf("device: %v", err)
	}
}

// listen serves d on 127.0.0.1 until the test ends and returns its address.
func (d *device) listen(tb testing.TB) string {
	tb.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(tb.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		tb.Fatal("the listener is no TCPListener")
	}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			d.wg.Go(func() { d.serve(conn) })
		}
	}()
	tb.Cleanup(func() {
		d.answer()
		d.note(ln.Close())
		<-accepted
		d.wg.Wait()
	})
	return ln.Addr().String()
}

// answer lets the device answer its held request.
func (d *device) answer() {
	d.answered.Do(func() { close(d.release) })
}

// frozenConn is the device's end of a connection, which drops every byte it reads
// once the device froze.
type frozenConn struct {
	net.Conn

	d *device
}

// Read reads from the connection what the device takes.
func (c *frozenConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil {
			return n, fmt.Errorf("device: %w", err)
		}
		if !c.d.frozen.Load() {
			return n, nil
		}
	}
}

// serve serves one connection.
func (d *device) serve(conn *net.TCPConn) {
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	sc, chans, reqs, err := ssh.NewServerConn(&frozenConn{Conn: conn, d: d}, d.config)
	if err != nil {
		d.note(errors.Join(err, conn.Close()))
		return
	}
	d.wg.Go(func() { ssh.DiscardRequests(reqs) })
	for nc := range chans {
		ch, chReqs, err := nc.Accept()
		if err != nil {
			d.note(err)
			continue
		}
		d.wg.Go(func() { d.session(ch, chReqs) })
	}
	d.note(sc.Close())
}

// session answers the requests of one session and plays the shell.
func (d *device) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == d.held {
			d.asked <- struct{}{}
			<-d.release
		}
		d.note(req.Reply(req.Type != d.refuse, nil))
		switch req.Type {
		case d.refuse:
		case "shell":
			d.wg.Go(func() { d.shell(ch) })
		case "window-change":
			d.resized <- [2]uint32{binary.BigEndian.Uint32(req.Payload), binary.BigEndian.Uint32(req.Payload[4:])}
		}
	}
	d.note(ch.Close())
}

// exit ends the shell of ch with status.
func (d *device) exit(ch ssh.Channel, status uint32) {
	_, err := ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
	d.note(errors.Join(err, ch.Close()))
}

// cut closes every connection of the device.
func (d *device) cut() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, conn := range d.conns {
		d.note(conn.Close())
	}
}

// reset resets every connection of the device: its close sends a reset, not a FIN.
func (d *device) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, conn := range d.conns {
		d.note(errors.Join(conn.SetLinger(0), conn.Close()))
	}
}

// login runs a login of the page by password: it sends connect and returns at ready.
func (r *run) login(t *testing.T, connect string) {
	t.Helper()
	r.send(t, connect)
	r.expect(t, "ready")
}

// loginWithKey runs a login of the page by its key: it sends connect, answers every
// sign request with keyring, and returns at ready.
func (r *run) loginWithKey(t *testing.T, connect string, keyring agent.ExtendedAgent) {
	t.Helper()
	r.send(t, connect)
	for {
		m := r.expect(t, "")
		switch m["type"] {
		case "ready":
			return
		case "sign":
			r.sign(t, keyring, m)
		}
	}
}

// sign answers the sign request m with keyring's signature.
func (r *run) sign(t *testing.T, keyring agent.ExtendedAgent, m map[string]any) {
	t.Helper()
	text, ok := m["data"].(string)
	if !ok {
		t.Fatalf("sign request %v", m)
	}
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	flags, ok := m["flags"].(float64)
	if !ok {
		t.Fatalf("sign request %v", m)
	}
	sig, err := keyring.SignWithFlags(keys[0], data, agent.SignatureFlags(flags))
	if err != nil {
		t.Fatal(err)
	}
	id, ok := m["id"].(float64)
	if !ok {
		t.Fatalf("sign request %v", m)
	}
	r.send(t, fmt.Sprintf(`{"type":"signature","id":%d,"signature":%q}`, int(id),
		base64.StdEncoding.EncodeToString(ssh.Marshal(sig))))
}

// refuseChallenges answers every challenge with a wrong password until the WebSocket
// closes, and returns its close code.
func (r *run) refuseChallenges(t *testing.T) websocket.StatusCode {
	t.Helper()
	for {
		_, data, err := r.page.Read(t.Context())
		if err != nil {
			<-r.done
			return websocket.CloseStatus(err)
		}
		if bytes.Contains(data, []byte(`"type":"challenge"`)) {
			r.send(t, `{"type":"answers","answers":["wrong"]}`)
		}
	}
}

// noPage is the Page of a login by the typed password, which never asks the page.
type noPage struct{}

// HostKey drops the host key.
func (noPage) HostKey(string, string) {}

// Sign refuses.
func (noPage) Sign(context.Context, []byte, uint32) ([]byte, error) { return nil, errRefusedByDevice }

// Answer refuses.
func (noPage) Answer(context.Context, protocol.Challenge) ([]secret.Value, error) {
	return nil, errRefusedByDevice
}

// Banner drops the banner.
func (noPage) Banner(context.Context, string) error { return nil }

// interactiveDevice returns a device asking one keyboard-interactive round of two
// prompts.
func interactiveDevice(t *testing.T) *device {
	t.Helper()
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.config.PasswordCallback = nil
	d.config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, c ssh.KeyboardInteractiveChallenge) (
		*ssh.Permissions, error,
	) {
		if _, err := c("", "", []string{"Password: ", "Code: "}, []bool{false, true}); err != nil {
			return nil, fmt.Errorf("challenge: %w", err)
		}
		return nil, errRefusedByDevice
	}
	return d
}

// forwardSession returns a session whose shell, on a device on loopback, runs shell.
func forwardSession(tb testing.TB, shell func(d *device, ch ssh.Channel)) (s *session, stop func()) {
	tb.Helper()
	t := tb
	d := newDevice(t, shell)
	target := d.listen(t)
	client, err := sshclient.Dial(t.Context(), &testConfig().SSH, target,
		protocol.Login{User: testUser, Password: secret.New(testPassword)}, noPage{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sh, err := client.Open(t.Context(), protocol.Size{Cols: 80, Rows: 24}, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s = &session{client: client, shell: sh}
	return s, func() {
		if err := client.Close(); err != nil {
			t.Log(err)
		}
	}
}

// outputSession returns a session over a pipe whose page drains every frame.
func outputSession(tb testing.TB) (s *session, stop func()) {
	tb.Helper()
	bridge, page := wsPair(tb.Context(), tb, plain)
	s, _, release := newSession(tb.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
		discardLogger())
	total := drain(page)
	return s, func() {
		release()
		if err := errors.Join(bridge.CloseNow(), page.CloseNow()); err != nil {
			tb.Log(err)
		}
		<-total
	}
}

// discardInput reads the shell's input until it ends.
func discardInput(d *device, ch ssh.Channel) {
	_, err := io.Copy(io.Discard, ch)
	d.note(errors.Join(err, ch.Close()))
}
