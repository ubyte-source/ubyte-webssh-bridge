package server

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// addressCase is a request of the client address table: its TCP peer, its headers and
// the trusted prefixes, with the client and the peer clientAddress must find.
type addressCase struct {
	name         string
	remote       string
	forwarded    []string
	realIPText   string
	trusted      []string
	client, peer string
}

// addressCases returns the cases of section 7.1 of the client address.
func addressCases() []addressCase {
	loopback := []string{"127.0.0.0/8", "::1/128"}
	proxies := []string{"127.0.0.0/8", "192.0.2.0/24"}
	return []addressCase{
		{name: "untrusted peer", remote: "198.51.100.9:4000", forwarded: []string{"203.0.113.7"},
			realIPText: "203.0.113.8", trusted: loopback, client: "198.51.100.9", peer: "198.51.100.9"},
		{name: "one hop", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.7"}, trusted: loopback,
			client: "203.0.113.7", peer: "127.0.0.1"},
		{name: "several hops", remote: "127.0.0.1:4000", forwarded: []string{"198.51.100.9, 203.0.113.7, 192.0.2.1"},
			trusted: proxies, client: "203.0.113.7", peer: "127.0.0.1"},
		{name: "every entry trusted", remote: "127.0.0.1:4000", forwarded: []string{"192.0.2.5,\t192.0.2.6"},
			trusted: proxies, client: "192.0.2.5", peer: "127.0.0.1"},
		{name: "unknown in the middle", remote: "127.0.0.1:4000",
			forwarded: []string{"198.51.100.9, unknown, 192.0.2.6"}, trusted: proxies, client: "192.0.2.6",
			peer: "127.0.0.1"},
		{name: "a zone in the middle", remote: "127.0.0.1:4000",
			forwarded: []string{"198.51.100.9, fe80::1%eth0, 192.0.2.6"}, trusted: proxies, client: "192.0.2.6",
			peer: "127.0.0.1"},
		{name: "unknown at the right", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.7, unknown"},
			trusted: loopback, client: "127.0.0.1", peer: "127.0.0.1"},
		{name: "an empty value", remote: "127.0.0.1:4000", forwarded: []string{""}, realIPText: "203.0.113.8",
			trusted: loopback, client: "127.0.0.1", peer: "127.0.0.1"},
		{name: "X-Real-IP alone", remote: "127.0.0.1:4000", realIPText: " 203.0.113.8 ", trusted: loopback,
			client: "203.0.113.8", peer: "127.0.0.1"},
		{name: "X-Real-IP unreadable", remote: "127.0.0.1:4000", realIPText: "unknown", trusted: loopback,
			client: "127.0.0.1", peer: "127.0.0.1"},
		{name: "X-Real-IP with a zone", remote: "127.0.0.1:4000", realIPText: "fe80::1%eth0", trusted: loopback,
			client: "127.0.0.1", peer: "127.0.0.1"},
		{name: "X-Real-IP beside X-Forwarded-For", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.7"},
			realIPText: "203.0.113.8", trusted: loopback, client: "203.0.113.7", peer: "127.0.0.1"},
		{name: "IPv6", remote: "[::1]:4000", forwarded: []string{"2001:db8::7"}, trusted: loopback,
			client: "2001:db8::7", peer: "::1"},
		{name: "IPv4-mapped", remote: "[::ffff:192.0.2.1]:4000", forwarded: []string{"::ffff:203.0.113.7"},
			trusted: proxies, client: "203.0.113.7", peer: "192.0.2.1"},
		{name: "two header lines", remote: "127.0.0.1:4000", forwarded: []string{"198.51.100.9", "192.0.2.5"},
			trusted: proxies, client: "198.51.100.9", peer: "127.0.0.1"},
		{name: "no TCP peer", remote: "pipe", forwarded: []string{"203.0.113.7"}, trusted: loopback,
			client: "invalid IP", peer: "invalid IP"},
	}
}

// addressRequest returns the request of tc, with a Forwarded header that no proxy
// walk reads.
func addressRequest(t *testing.T, tc *addressCase) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws", http.NoBody)
	r.RemoteAddr = tc.remote
	r.Header["X-Forwarded-For"] = tc.forwarded
	if tc.realIPText != "" {
		r.Header.Set("X-Real-IP", tc.realIPText)
	}
	r.Header.Set("Forwarded", "for=198.51.100.200")
	return r
}

func prefixes(texts []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(texts))
	for _, s := range texts {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// TestClientAddressWalksTheTrustedProxies finds the client and the peer of each case
// of addressCases.
func TestClientAddressWalksTheTrustedProxies(t *testing.T) {
	cases := addressCases()
	for i := range cases {
		tc := &cases[i]
		client, peer := clientAddress(addressRequest(t, tc), prefixes(tc.trusted))
		if client.String() != tc.client || peer.String() != tc.peer {
			t.Errorf("%s: clientAddress() = %s, %s, want %s, %s", tc.name, client, peer, tc.client, tc.peer)
		}
	}
}

// referenceClient walks the entries of the X-Forwarded-For lines from the rightmost
// back through the addresses trust holds, as nginx's real_ip_recursive does.
func referenceClient(peer netip.Addr, lines []string, realIPText string, trust func(netip.Addr) bool) netip.Addr {
	if !trust(peer) {
		return peer
	}
	if len(lines) == 0 {
		addr, err := netip.ParseAddr(strings.Trim(realIPText, " \t"))
		if err != nil || addr.Zone() != "" {
			return peer
		}
		return addr.Unmap()
	}
	var entries []string
	for _, line := range lines {
		entries = append(entries, strings.Split(line, ",")...)
	}
	last := peer
	for _, entry := range slices.Backward(entries) {
		addr, err := netip.ParseAddr(strings.Trim(entry, " \t"))
		if err != nil || addr.Zone() != "" {
			return last
		}
		last = addr.Unmap()
		if !trust(last) {
			return last
		}
	}
	return last
}

// FuzzClientAddress compares clientAddress with referenceClient on any TCP peer, two
// X-Forwarded-For lines, X-Real-IP and a choice of trusted prefixes.
func FuzzClientAddress(f *testing.F) {
	cases := addressCases()
	for i := range cases {
		f.Add(cases[i].remote, strings.Join(cases[i].forwarded, "\n"), cases[i].realIPText, uint8(3))
	}
	choices := prefixes([]string{"127.0.0.0/8", "::1/128", "192.0.2.0/24", "2001:db8::/32", "0.0.0.0/0"})
	f.Fuzz(func(t *testing.T, remote, forwarded, realIPText string, mask uint8) {
		var trusted []netip.Prefix
		for i, p := range choices {
			if mask&(1<<i) != 0 {
				trusted = append(trusted, p)
			}
		}
		tc := addressCase{remote: remote, realIPText: realIPText}
		if forwarded != "" {
			tc.forwarded = strings.Split(forwarded, "\n")
		}
		client, peer := clientAddress(addressRequest(t, &tc), trusted)
		ap, err := netip.ParseAddrPort(remote)
		wantPeer := ap.Addr().Unmap()
		if err != nil {
			wantPeer = netip.Addr{}
		}
		want := referenceClient(wantPeer, tc.forwarded, realIPText, func(a netip.Addr) bool {
			return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(a) })
		})
		if client != want || peer != wantPeer {
			t.Fatalf("clientAddress(%q, %q, %q) = %s, %s, want %s, %s", remote, tc.forwarded, realIPText, client, peer,
				want, wantPeer)
		}
	})
}

// awaitRefused returns the first refused record of r whose reason is reason, waiting
// for it, and fails t unless it carries the mark of the serve context.
func awaitRefused(t *testing.T, r *running, reason string) map[string]any {
	t.Helper()
	var found map[string]any
	if !waitUntil(func() bool {
		for _, rec := range r.log.records("refused") {
			if rec["reason"] == reason {
				found = rec
				return true
			}
		}
		return false
	}) {
		t.Fatalf("no refused record of %s within %v; records:\n%s", reason, awaitBound, r.log.String())
	}
	if found["mark"] != testMark {
		t.Errorf("refused record = %v, want the mark %q of the serve context", found, testMark)
	}
	return found
}

// get sends a GET of path with header through the client of r and returns the status
// and the body of the answer.
func (r *running) get(t *testing.T, path string, header http.Header) (status int, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, r.url(path), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest(%s) = %v, want nil", path, err)
	}
	maps.Copy(req.Header, header)
	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s = %v, want a response", path, err)
	}
	defer closeBody(t, resp)
	var b strings.Builder
	if _, err = io.Copy(&b, resp.Body); err != nil {
		t.Fatalf("read the body of %s = %v, want nil", path, err)
	}
	return resp.StatusCode, b.String()
}

// TestServeSocketRefusesWithoutOrigin sends the upgrade without Origin through a
// trusted proxy: 403 origin required, and the record names the client the proxy
// forwarded and the peer.
func TestServeSocketRefusesWithoutOrigin(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	status, body := r.get(t, "/ws", http.Header{"X-Forwarded-For": {"203.0.113.7"}})
	if status != http.StatusForbidden || body != "origin required\n" {
		t.Errorf("GET /ws without Origin = %d %q, want 403 origin required", status, body)
	}
	rec := awaitRefused(t, r, refusedOrigin)
	if rec["client"] != "203.0.113.7" || rec["peer"] != "127.0.0.1" || rec["level"] != "DEBUG" || rec["target"] != nil {
		t.Errorf("refused record = %v, want client 203.0.113.7, peer 127.0.0.1, at debug, no target", rec)
	}
}

// TestServeSocketRefusesAnInvalidTarget dials paths that name no target on the path
// route: 400 invalid target and a record without a peer.
func TestServeSocketRefusesAnInvalidTarget(t *testing.T) {
	r := serveTest(t, testConfig(""))
	for _, path := range []string{"/ws/a%20b/22", "/ws/192.0.2.10/0", "/ws/192.0.2.10/+22"} {
		if _, hs, err := r.dial(t, path); err == nil || hs.status != http.StatusBadRequest {
			t.Errorf("dial %s = %d, %v, want 400", path, hs.status, err)
		}
	}
	if rec := awaitRefused(t, r, refusedTarget); rec["client"] != "127.0.0.1" || rec["peer"] != nil {
		t.Errorf("refused record = %v, want client 127.0.0.1 and no peer", rec)
	}
}

// TestServeSocketRefusesAForeignOrigin dials with the Origin of another site: 403 from
// the upgrade, logged with its error.
func TestServeSocketRefusesAForeignOrigin(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	_, hs, err := r.dialWith(t, "/ws", http.Header{"Origin": {"https://evil.example.test"}})
	if err == nil || hs.status != http.StatusForbidden {
		t.Errorf("upgrade from a foreign Origin = %d, %v, want 403", hs.status, err)
	}
	if rec := awaitRefused(t, r, refusedUpgrade); rec["target"] != testTarget || rec["error"] == nil {
		t.Errorf("refused record = %v, want the target and the error", rec)
	}
}

// TestServeSocketClosesBusy fills the caps and dials: the session closes with 4007 and
// its reason.
func TestServeSocketClosesBusy(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	admits(r.server.caps, r.server.cfg.Conn.MaxTotal)
	conn, _, err := r.dial(t, "/ws")
	if err != nil {
		t.Fatalf("dial /ws = %v, want the handshake", err)
	}
	if got := closeStatus(t, conn); got != websocket.StatusCode(protocol.CloseBusy) {
		t.Errorf("close status = %d, want %d", got, protocol.CloseBusy)
	}
	awaitRefused(t, r, refusedBusy)
}

// TestServeSocketKeysTheRateByTheForwardedClient gives each client one session an hour
// and spends the one of a client behind the trusted proxy: its next session closes with
// 4008 while another client passes the rate and meets the full caps.
func TestServeSocketKeysTheRateByTheForwardedClient(t *testing.T) {
	cfg := testConfig(testTarget)
	cfg.Rate.Burst, cfg.Rate.Interval = 1, time.Hour
	r := serveTest(t, cfg)
	admits(r.server.caps, cfg.Conn.MaxTotal)
	for _, tc := range []struct {
		client string
		want   protocol.CloseCode
	}{
		{"203.0.113.7", protocol.CloseBusy}, {"203.0.113.7", protocol.CloseRateLimited},
		{"203.0.113.8", protocol.CloseBusy},
	} {
		conn, _, err := r.dialWith(t, "/ws", http.Header{"Origin": {"https://" + r.addr},
			"X-Forwarded-For": {tc.client}})
		if err != nil {
			t.Fatalf("dial /ws from %s = %v, want the handshake", tc.client, err)
		}
		if got := closeStatus(t, conn); got != websocket.StatusCode(tc.want) {
			t.Errorf("close status of %s = %d, want %d", tc.client, got, tc.want)
		}
	}
	if rec := awaitRefused(t, r, refusedRate); rec["client"] != "203.0.113.7" || rec["peer"] != "127.0.0.1" {
		t.Errorf("refused record = %v, want client 203.0.113.7 and peer 127.0.0.1", rec)
	}
}

// TestServeSocketLogsAFailedClose closes the client at once after the handshake: the
// refusal record carries the failure of the close.
func TestServeSocketLogsAFailedClose(t *testing.T) {
	r := serveTest(t, testConfig(testTarget))
	admits(r.server.caps, r.server.cfg.Conn.MaxTotal)
	conn, _, err := r.dial(t, "/ws")
	if err != nil {
		t.Fatalf("dial /ws = %v, want the handshake", err)
	}
	if err := conn.CloseNow(); err != nil {
		t.Fatalf("CloseNow() = %v, want nil", err)
	}
	if rec := awaitRefused(t, r, refusedBusy); rec["error"] == nil {
		t.Errorf("refused record = %v, want the error of the close", rec)
	}
}

// TestServeSocketRunsASession dials the route of each mode, the path's through the
// trusted proxy: the session runs, names the peer only when it is not the client,
// holds its place in the caps while it runs, and gives it back once the page closes.
func TestServeSocketRunsASession(t *testing.T) {
	for _, tc := range []struct {
		route, path  string
		header       http.Header
		client, peer any
	}{
		{testTarget, "/ws", http.Header{}, "127.0.0.1", nil},
		{"", "/ws/192.0.2.10/22", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", "127.0.0.1"},
	} {
		r := serveTest(t, testConfig(tc.route))
		tc.header.Set("Origin", "https://"+r.addr)
		conn, _, err := r.dialWith(t, tc.path, tc.header)
		if err != nil {
			t.Fatalf("dial %s = %v, want the handshake", tc.path, err)
		}
		if !waitUntil(func() bool { return r.server.caps.total.Load() == 1 }) {
			t.Fatalf("dial %s: caps total = %d, want the session counted", tc.path, r.server.caps.total.Load())
		}
		if !waitUntil(func() bool { return len(r.log.records("session started")) == 1 }) {
			t.Fatalf("dial %s: no session started record within %v", tc.path, awaitBound)
		}
		if started := r.log.record(t, "session started"); started["client"] != tc.client || started["peer"] != tc.peer {
			t.Errorf("dial %s: record %v, want client %v and peer %v", tc.path, started, tc.client, tc.peer)
		}
		if err := conn.Close(websocket.StatusNormalClosure, ""); err != nil {
			t.Logf("Close() = %v", err)
		}
		if !waitUntil(func() bool { return r.server.caps.total.Load() == 0 }) {
			t.Errorf("dial %s: caps total = %d after the page closed, want 0", tc.path, r.server.caps.total.Load())
		}
	}
}

// TestServeSocketReleasesTheSlot holds the one session MaxTotal allows: another closes
// with 4007, and once the first ends a new one runs.
func TestServeSocketReleasesTheSlot(t *testing.T) {
	cfg := testConfig(testTarget)
	cfg.Conn.MaxTotal = 1
	r := serveTest(t, cfg)
	first, _, err := r.dial(t, "/ws")
	if err != nil || !waitUntil(func() bool { return r.server.caps.total.Load() == 1 }) {
		t.Fatalf("dial /ws = %v, total %d, want a session", err, r.server.caps.total.Load())
	}
	second, _, err := r.dial(t, "/ws")
	if err != nil || closeStatus(t, second) != websocket.StatusCode(protocol.CloseBusy) {
		t.Fatalf("second dial = %v, want a close with 4007", err)
	}
	if err = first.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Logf("Close() = %v", err)
	}
	if !waitUntil(func() bool { return r.server.caps.total.Load() == 0 }) {
		t.Fatal("the first session kept its slot after the page closed, want it released")
	}
	third, _, err := r.dial(t, "/ws")
	if err != nil || !waitUntil(func() bool { return r.server.caps.total.Load() == 1 }) {
		t.Fatalf("third dial = %v, total %d, want a session", err, r.server.caps.total.Load())
	}
	if err := third.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Logf("Close() = %v", err)
	}
}
