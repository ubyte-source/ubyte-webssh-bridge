package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"testing"

	"github.com/ubyte-source/ubyte-webssh-bridge/frontend"
)

// policyHeaders returns the headers withPolicy sets, with their values.
func policyHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
			"img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-cache",
	}
}

// checkPolicy fails t unless header holds every header of policyHeaders.
func checkPolicy(t *testing.T, what string, header http.Header) {
	t.Helper()
	for name, want := range policyHeaders() {
		if got := header.Get(name); got != want {
			t.Errorf("%s: %s = %q, want %q", what, name, got, want)
		}
	}
}

// TestWithPolicySetsEveryHeader requests a file, a missing file and a refused method
// through the handler, and opens a WebSocket that the caps close: every response
// carries the policy headers.
func TestWithPolicySetsEveryHeader(t *testing.T) {
	handler := New(testConfig(testTarget), nil).handler
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/"}, {http.MethodGet, "/missing.js"}, {http.MethodPost, "/"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, http.NoBody))
		checkPolicy(t, tc.method+" "+tc.target, rec.Result().Header)
	}
	r := serveTest(t, testConfig(testTarget))
	admits(r.server.caps, r.server.cfg.Conn.MaxTotal)
	conn, hs, err := r.dial(t, "/ws")
	if err != nil {
		t.Fatalf("dial /ws = %v, want the handshake", err)
	}
	checkPolicy(t, "the WebSocket handshake", hs.header)
	closeStatus(t, conn)
}

// metaPolicy matches the Content-Security-Policy of a meta element.
var metaPolicy = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`)

// TestContentPolicyEqualsTheMetaOfIndex reads the policy index.html repeats: the header
// is it with frame-ancestors, which a meta element cannot carry.
func TestContentPolicyEqualsTheMetaOfIndex(t *testing.T) {
	index, err := fs.ReadFile(frontend.Files(), path.Join(frontend.Root, indexFile))
	if err != nil {
		t.Fatalf("read index.html = %v, want nil", err)
	}
	m := metaPolicy.FindSubmatch(index)
	if len(m) != 2 || string(m[1])+"; frame-ancestors 'none'" != contentPolicy {
		t.Errorf("index.html's meta policy = %q, want %q without its frame-ancestors", m, contentPolicy)
	}
}
