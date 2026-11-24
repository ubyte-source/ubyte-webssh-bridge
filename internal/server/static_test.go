package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/ubyte-source/ubyte-webssh-bridge/frontend"
)

// serveRequest sends a request of method to target through the handler of a Server of
// the route of route and returns the recorded response.
func serveRequest(t *testing.T, route, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	New(testConfig(route), nil).handler.ServeHTTP(rec,
		httptest.NewRequestWithContext(t.Context(), method, target, http.NoBody))
	return rec
}

// pageFiles returns the path of every file of the page.
func pageFiles(t *testing.T) []string {
	t.Helper()
	var names []string
	err := fs.WalkDir(frontend.Files(), frontend.Root, func(name string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, name)
		}
		return err
	})
	if err != nil || len(names) == 0 {
		t.Fatalf("walk the page = %d files, %v, want some and nil", len(names), err)
	}
	return names
}

// TestServeFileServesEveryFile requests every file of the page, / for index.html: each
// answers 200 with its bytes and the media type of its extension.
func TestServeFileServesEveryFile(t *testing.T) {
	types := map[string]string{
		".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
		".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
	}
	files := frontend.Files()
	names := pageFiles(t)
	for _, name := range names {
		want, err := fs.ReadFile(files, name)
		if err != nil {
			t.Fatalf("read %s = %v, want nil", name, err)
		}
		target := strings.TrimPrefix(name, frontend.Root)
		if target == "/"+indexFile {
			target = "/"
		}
		rec := serveRequest(t, testTarget, http.MethodGet, target)
		if rec.Code != http.StatusOK || rec.Body.String() != string(want) ||
			rec.Header().Get("Content-Type") != types[path.Ext(name)] {
			t.Errorf("GET %s = %d, %s, %d bytes, want 200, %s and its %d bytes", target, rec.Code,
				rec.Header().Get("Content-Type"), rec.Body.Len(), types[path.Ext(name)], len(want))
		}
	}
}

// TestServeFileAnswersNotFound requests what is no regular file of the page: each
// answers 404 not found, the routes of the other mode included.
func TestServeFileAnswersNotFound(t *testing.T) {
	for _, tc := range []struct{ route, target string }{
		{testTarget, "/javascript/"}, {testTarget, "/javascript"}, {testTarget, "/missing.js"},
		{testTarget, "/ws/a/1"}, {"", "/ws"}, {testTarget, "/public/index.html"}, {testTarget, "/%00"},
	} {
		rec := serveRequest(t, tc.route, http.MethodGet, tc.target)
		if rec.Code != http.StatusNotFound || rec.Body.String() != "not found\n" {
			t.Errorf("GET %s (target %q) = %d %q, want 404 not found", tc.target, tc.route, rec.Code, rec.Body)
		}
	}
}

// TestServeFileRefusesOtherMethods posts to / and to a file: 405 with Allow, and HEAD
// answers as GET does without a body.
func TestServeFileRefusesOtherMethods(t *testing.T) {
	for _, target := range []string{"/", "/favicon.svg"} {
		rec := serveRequest(t, testTarget, http.MethodPost, target)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("POST %s = %d, Allow %q, want 405 and GET, HEAD", target, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if rec := serveRequest(t, testTarget, http.MethodHead, "/"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD / = %d, %d bytes, want 200 without a body", rec.Code, rec.Body.Len())
	}
}

// TestContentTypeOfEachExtension names the media type of each extension of the page,
// and of any other.
func TestContentTypeOfEachExtension(t *testing.T) {
	for ext, want := range map[string]string{
		".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
		".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".map": "application/octet-stream",
	} {
		if got := contentType(ext); got != want {
			t.Errorf("contentType(%s) = %q, want %q", ext, got, want)
		}
	}
}
