package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// errHalt is the cause a test stops a server with.
var errHalt = errors.New("test halted")

// TestNewRoutesEachMode dials the WebSocket of each mode with full caps, so the
// handshake answers without a session: the route of the mode upgrades and the route
// of the other mode answers 404.
func TestNewRoutesEachMode(t *testing.T) {
	for _, tc := range []struct{ route, upgrades, missing string }{
		{testTarget, "/ws", "/ws/192.0.2.10/22"}, {"", "/ws/192.0.2.10/22", "/ws"},
	} {
		r := serveTest(t, testConfig(tc.route))
		admits(r.server.caps, r.server.cfg.Conn.MaxTotal)
		conn, hs, err := r.dial(t, tc.upgrades)
		if err != nil || hs.status != http.StatusSwitchingProtocols {
			t.Fatalf("target %q: dial %s = %d, %v, want 101", tc.route, tc.upgrades, hs.status, err)
		}
		if got := closeStatus(t, conn); got != websocket.StatusCode(protocol.CloseBusy) {
			t.Errorf("target %q: close status = %d, want %d", tc.route, got, protocol.CloseBusy)
		}
		if _, hs, err := r.dial(t, tc.missing); err == nil || hs.status != http.StatusNotFound {
			t.Errorf("target %q: dial %s = %d, %v, want 404", tc.route, tc.missing, hs.status, err)
		}
	}
}

// TestNewCapsEachRoute admits sessions of one target past the per-host cap: the
// pinned route holds the cap of the process alone, the path route the per-host cap.
func TestNewCapsEachRoute(t *testing.T) {
	log, _ := newLogger()
	for route, want := range map[string]int{testTarget: 4, "": 2} {
		if got := admits(New(testConfig(route), log).caps, 4); got != want {
			t.Errorf("target %q: %d of 4 admissions granted, want %d", route, got, want)
		}
	}
}

// TestPathTargetWrapsTheInvalidTarget reads a path whose host is no host name: the
// error is config.ErrInvalidTarget.
func TestPathTargetWrapsTheInvalidTarget(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws/a%20b/22", http.NoBody)
	r.SetPathValue("host", "a b")
	r.SetPathValue("port", "22")
	if _, err := pathTarget(r); !errors.Is(err, config.ErrInvalidTarget) {
		t.Errorf("pathTarget(a b) = %v, want config.ErrInvalidTarget", err)
	}
}

// tlsConn opens a TLS connection to the server of r.
func (r *running) tlsConn(t *testing.T) net.Conn {
	t.Helper()
	d := tls.Dialer{Config: r.tlsConfig()}
	conn, err := d.DialContext(t.Context(), "tcp", r.addr)
	if err != nil {
		t.Fatalf("tls dial %s = %v, want nil", r.addr, err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close the TLS connection the server may have closed = %v", err)
		}
	})
	return conn
}

// statusOf sends request over a new TLS connection to r and returns the status line of
// the answer.
func statusOf(t *testing.T, r *running, request string) string {
	t.Helper()
	conn := r.tlsConn(t)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write the request = %v, want nil", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read the status line = %v, want one", err)
	}
	return strings.TrimSpace(line)
}

// lifeKey keys the value that marks a lifetime context of a test.
type lifeKey struct{}

// TestServerHTTPServerBoundsEachConnection builds the HTTP server: TLS 1.2 or higher,
// the handshake timeout on the request, 60 s on a response, 120 s idle, 16384 bytes of
// headers, and every request under the lifetime context.
func TestServerHTTPServerBoundsEachConnection(t *testing.T) {
	log, _ := newLogger()
	cfg := testConfig(testTarget)
	cfg.WS.HandshakeTimeout = 7 * time.Second
	life := context.WithValue(t.Context(), lifeKey{}, "life")
	srv := New(cfg, log).httpServer(life)
	if srv.TLSConfig.MinVersion != tls.VersionTLS12 || len(srv.TLSConfig.Certificates) != 1 ||
		srv.ReadHeaderTimeout != 7*time.Second || srv.ReadTimeout != 7*time.Second ||
		srv.WriteTimeout != 60*time.Second || srv.IdleTimeout != 120*time.Second || srv.MaxHeaderBytes != 16384 ||
		srv.BaseContext(nil) != life || srv.ErrorLog == nil {
		t.Errorf("httpServer() = %+v, want the bounds of each connection", srv)
	}
}

// TestServeBoundsTheRequestHeaders sends a request line and headers of 20480 bytes,
// which pass, and of 20481, which 431 refuses.
func TestServeBoundsTheRequestHeaders(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	head := "GET / HTTP/1.1\r\nHost: " + r.addr + "\r\nConnection: close\r\nX-Pad: "
	for size, want := range map[int]string{
		20480: "HTTP/1.1 200 OK", 20481: "HTTP/1.1 431 Request Header Fields Too Large",
	} {
		request := head + strings.Repeat("a", size-len(head)-len("\r\n\r\n")) + "\r\n\r\n"
		if got := statusOf(t, r, request); got != want {
			t.Errorf("a request of %d bytes = %q, want %q", len(request), got, want)
		}
	}
}

// TestServeLogsServingAndStopping serves and stops: serving names the listener's
// address, stopping the cause of the stop, both under the serve context, and Serve
// returns nil.
func TestServeLogsServingAndStopping(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	if !waitUntil(func() bool { return len(r.log.records("serving")) == 1 }) {
		t.Fatalf("no serving record within %v", awaitBound)
	}
	if err := r.halt(t); err != nil {
		t.Errorf("Serve() after the stop = %v, want nil", err)
	}
	serving, stopping := r.log.record(t, "serving"), r.log.record(t, "stopping")
	if serving["address"] != r.addr || serving["level"] != "INFO" || serving["mark"] != testMark ||
		stopping["cause"] != errHalt.Error() || stopping["mark"] != testMark {
		t.Errorf("records serving %v, stopping %v, want the address, the cause %q and the mark", serving, stopping,
			errHalt)
	}
	if got := r.log.records("stop outlasted the budget"); len(got) != 0 {
		t.Errorf("records %v, want no stop past the budget", got)
	}
}

// TestServeLogsTLSErrorsAtDebug sends bytes that are no TLS handshake: net/http's
// record of it is at debug.
func TestServeLogsTLSErrorsAtDebug(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", r.addr)
	if err != nil {
		t.Fatalf("dial %s = %v, want nil", r.addr, err)
	}
	if _, err = conn.Write([]byte("\x00\x01\x02\x03\x04\x05")); err != nil {
		t.Fatalf("write = %v, want nil", err)
	}
	if !waitUntil(func() bool { return strings.Contains(r.log.String(), "TLS handshake error") }) {
		t.Errorf("records %s, want the TLS handshake error", r.log.String())
	}
	if !strings.Contains(r.log.String(), `"level":"DEBUG","msg":"http: TLS handshake error`) {
		t.Errorf("records %s, want the TLS handshake error at debug", r.log.String())
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close = %v, want nil", err)
	}
}

// holdRequest starts New(cfg) with a handler that holds the request it gets until the
// test ends, sends one over a new TLS connection and returns the server and the
// connection once the handler holds it.
func holdRequest(t *testing.T, cfg *config.Config) (*running, net.Conn) {
	t.Helper()
	log, buffer := newLogger()
	s := New(cfg, log)
	held, release := make(chan struct{}), make(chan struct{})
	s.handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(held)
		<-release
	})
	r := serve(t, s, buffer)
	t.Cleanup(func() { close(release) })
	conn := r.tlsConn(t)
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", r.addr); err != nil {
		t.Fatalf("write = %v, want nil", err)
	}
	select {
	case <-held:
	case <-time.After(awaitBound):
		t.Fatalf("the handler got no request within %v", awaitBound)
	}
	return r, conn
}

// TestServeStopOutlastsTheBudget holds a request in its handler past a budget of 1 s:
// the shutdown ends on the budget, the stop closes the connection, logs at error under
// the serve context and Serve returns nil.
func TestServeStopOutlastsTheBudget(t *testing.T) {
	cfg := testConfig(testTarget)
	cfg.Server.ShutdownTimeout = time.Second
	r, conn := holdRequest(t, cfg)
	if err := r.halt(t); err != nil {
		t.Errorf("Serve() after the stop = %v, want nil", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(awaitBound)); err != nil {
		t.Fatalf("SetReadDeadline() = %v, want nil", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("read the held connection = %v, want io.EOF", err)
	}
	recs := r.log.records("stop outlasted the budget")
	if len(recs) != 1 || recs[0]["level"] != "ERROR" || recs[0]["timeout"] != float64(time.Second) ||
		recs[0]["error"] != context.DeadlineExceeded.Error() || recs[0]["mark"] != testMark {
		t.Errorf("records %v, want one at error with the timeout of 1s, the deadline of the shutdown and the mark",
			recs)
	}
}

// TestServeReturnsTheFailureOfTheListener serves on a closed listener: Serve returns
// the failure, wrapped.
func TestServeReturnsTheFailureOfTheListener(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	if err = ln.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	log, _ := newLogger()
	err = New(testConfig(testTarget), log).Serve(t.Context(), ln)
	if err == nil || !errors.Is(err, net.ErrClosed) || !strings.HasPrefix(err.Error(), "serve: ") {
		t.Errorf("Serve(a closed listener) = %v, want serve: and net.ErrClosed", err)
	}
}

// TestServerStopLogsPastTheBudget stops with a session that outlasts the budget: the
// stop waits the budget, then logs it at error.
func TestServerStopLogsPastTheBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, buffer := newLogger()
		cfg := testConfig(testTarget)
		cfg.Server.ShutdownTimeout = 3 * time.Second
		s := New(cfg, log)
		s.sessions.Add(1)
		ended := false
		start := time.Now()
		s.stop(t.Context(), &http.Server{ReadHeaderTimeout: time.Second}, func() { ended = true })
		s.sessions.Done()
		recs := buffer.records("stop outlasted the budget")
		if !ended || time.Since(start) != 3*time.Second || len(recs) != 1 ||
			!strings.Contains(fmt.Sprint(recs[0]["error"]), context.DeadlineExceeded.Error()) {
			t.Errorf("stop: ended %v after %v, records %v, want the lifetime ended, 3s and the deadline logged",
				ended, time.Since(start), recs)
		}
	})
}

// TestServeStopsTheSessions stops a server with a live session: the session closes
// with 1001 and Serve returns nil.
func TestServeStopsTheSessions(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	conn, _, err := r.dial(t, "/ws")
	if err != nil || !waitUntil(func() bool { return r.server.caps.total.Load() == 1 }) {
		t.Fatalf("dial /ws = %v, total %d, want a session", err, r.server.caps.total.Load())
	}
	status := make(chan websocket.StatusCode, 1)
	go func() { status <- closeStatus(t, conn) }()
	if err := r.halt(t); err != nil {
		t.Errorf("Serve() after the stop = %v, want nil", err)
	}
	if got := <-status; got != websocket.StatusCode(protocol.CloseGoingAway) {
		t.Errorf("close status = %d, want %d", got, protocol.CloseGoingAway)
	}
}

// TestServerDrainEndsWithTheContext drains a session that outlives a canceled
// context: the error is the context's.
func TestServerDrainEndsWithTheContext(t *testing.T) {
	log, _ := newLogger()
	s := New(testConfig(testTarget), log)
	s.sessions.Add(1)
	defer s.sessions.Done()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.drain(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("drain(a canceled context) = %v, want context.Canceled", err)
	}
}
