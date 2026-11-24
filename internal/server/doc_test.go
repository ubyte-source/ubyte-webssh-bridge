package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// TestMain runs the tests, failing on any goroutine they leave running.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// awaitBound bounds each wait of a test for the server.
const awaitBound = 10 * time.Second

// testTarget is the target of the pinned route and of the path the tests dial.
const testTarget = "192.0.2.10:22"

// admits returns how many of n admissions of testTarget c grants.
func admits(c *caps, n int) int {
	granted := 0
	for range n {
		if c.admit(testTarget) {
			granted++
		}
	}
	return granted
}

// testPair returns a self-signed certificate for 127.0.0.1 and the pool that trusts it.
func testPair(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey error = %v, want nil", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bridge.example.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate error = %v, want nil", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate error = %v, want nil", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// testConfig returns the configuration of the tests: the route of target ("" for the
// path route), the loopback trusted, and room for a few sessions.
func testConfig(target string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			TrustedProxies:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
			Address:         "127.0.0.1:0",
			ShutdownTimeout: 5 * time.Second,
		},
		Conn: config.ConnConfig{MaxTotal: 4, MaxPerHost: 2},
		Rate: config.RateConfig{Burst: 10, Interval: 2 * time.Second},
		SSH:  config.SSHConfig{Target: target, ConnectTimeout: 10 * time.Second, LoginTimeout: 120 * time.Second},
		WS:   config.WSConfig{HandshakeTimeout: 10 * time.Second},
	}
}

// logBuffer keeps the records a logger writes, from any goroutine.
type logBuffer struct {
	mu   sync.Mutex
	text strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.text.Write(p)
	return len(p), nil
}

// String returns every record written so far.
func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.String()
}

// records returns the records of msg written so far, each decoded into a map.
func (b *logBuffer) records(msg string) []map[string]any {
	var out []map[string]any
	for line := range strings.Lines(b.String()) {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// record returns the one record of msg written so far, failing t unless there is
// exactly one.
func (b *logBuffer) record(t *testing.T, msg string) map[string]any {
	t.Helper()
	recs := b.records(msg)
	if len(recs) != 1 {
		t.Fatalf("records of %q = %v, want one", msg, recs)
	}
	return recs[0]
}

// markKey keys the mark a test puts in a context, which every record under that
// context carries.
type markKey struct{}

// testMark is the mark of the context a test serves under.
const testMark = "serve"

// markHandler writes the records of its handler with the mark of their context.
type markHandler struct {
	slog.Handler
}

func (h markHandler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler's signature
	if mark, ok := ctx.Value(markKey{}).(string); ok {
		r.AddAttrs(slog.String("mark", mark))
	}
	return h.Handler.Handle(ctx, r) //nolint:wrapcheck // the test handler forwards the record
}

// newLogger returns a logger of JSON records from debug up, each with the mark of its
// context, written to a logBuffer.
func newLogger() (*slog.Logger, *logBuffer) {
	b := new(logBuffer)
	return slog.New(markHandler{slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})}), b
}

// marked returns ctx with the test's mark.
func marked(ctx context.Context) context.Context {
	return context.WithValue(ctx, markKey{}, testMark)
}

// waitUntil reports whether holds turns true within awaitBound, polling it.
func waitUntil(holds func() bool) bool {
	deadline := time.Now().Add(awaitBound)
	for !holds() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// running is a Server serving TLS on a loopback port of the test.
type running struct {
	server *Server
	log    *logBuffer
	client *http.Client
	pool   *x509.CertPool
	stop   context.CancelCauseFunc
	served chan error
	addr   string
}

// serveTest starts New(cfg) through serve, its records going to a new logBuffer.
func serveTest(t *testing.T, cfg *config.Config) *running {
	t.Helper()
	log, buffer := newLogger()
	return serve(t, New(cfg, log), buffer)
}

// serve starts s, whose records go to buffer, on a loopback port with a certificate of
// the test, under a context with the test's mark, and stops it when the test ends.
func serve(t *testing.T, s *Server, buffer *logBuffer) *running {
	t.Helper()
	pair, pool := testPair(t)
	s.cfg.Server.Certificate = pair
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", s.cfg.Server.Address)
	if err != nil {
		t.Fatalf("Listen(%s) = %v, want nil", s.cfg.Server.Address, err)
	}
	ctx, stop := context.WithCancelCause(marked(context.WithoutCancel(t.Context())))
	r := &running{server: s, log: buffer, pool: pool, stop: stop, served: make(chan error, 1),
		addr: ln.Addr().String()}
	r.client = &http.Client{Transport: &http.Transport{TLSClientConfig: r.tlsConfig()}}
	go func() { r.served <- r.server.Serve(ctx, ln) }()
	t.Cleanup(func() {
		r.client.CloseIdleConnections()
		if err := r.halt(t); err != nil {
			t.Errorf("Serve() = %v, want nil", err)
		}
	})
	return r
}

// tlsConfig returns the client TLS configuration that trusts the server of r.
func (r *running) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: r.pool, MinVersion: tls.VersionTLS12}
}

// halt stops the server of r once and returns what Serve returned.
func (r *running) halt(t *testing.T) error {
	t.Helper()
	r.stop(errHalt)
	select {
	case err, ok := <-r.served:
		if ok {
			close(r.served)
		}
		return err
	case <-time.After(awaitBound):
		t.Fatalf("Serve did not return within %v", awaitBound)
		return nil
	}
}

// url returns the https URL of path on the server of r.
func (r *running) url(path string) string {
	return "https://" + r.addr + path
}

// handshake is what the answer to a WebSocket upgrade shows: its status and headers.
type handshake struct {
	header http.Header
	status int
}

// dial opens a WebSocket to path with the Origin of the server itself and returns the
// connection and the handshake, or the handshake and the error of a refusal.
func (r *running) dial(t *testing.T, path string) (*websocket.Conn, handshake, error) {
	t.Helper()
	return r.dialWith(t, path, http.Header{"Origin": {"https://" + r.addr}})
}

// dialWith opens a WebSocket to path with header.
func (r *running) dialWith(t *testing.T, path string, header http.Header) (*websocket.Conn, handshake, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), awaitBound)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, "wss://"+r.addr+path,
		&websocket.DialOptions{HTTPClient: r.client, HTTPHeader: header})
	var h handshake
	if resp != nil {
		h = handshake{header: resp.Header, status: resp.StatusCode}
		closeBody(t, resp)
	}
	if err != nil {
		return nil, h, fmt.Errorf("dial %s: %w", path, err)
	}
	return conn, h, nil
}

func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.Body == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close the body = %v, want nil", err)
	}
}

// closeStatus reads conn until the server closes it and returns the close status.
func closeStatus(t *testing.T, conn *websocket.Conn) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), awaitBound)
	defer cancel()
	_, _, read := conn.Read(ctx)
	if err := conn.CloseNow(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("CloseNow() = %v, want nil", err)
	}
	return websocket.CloseStatus(read)
}
