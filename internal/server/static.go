package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/frontend"
)

// indexFile is the file of the path /.
const indexFile = "index.html"

// serveFile answers with the file of the page that the path of r names, or 404 for
// anything else: a directory, a missing file or a path fs.ValidPath refuses.
func serveFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = indexFile
	}
	data, err := fs.ReadFile(frontend.Files(), path.Join(frontend.Root, name))
	if !fs.ValidPath(name) || err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType(path.Ext(name)))
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// contentType returns the media type of a file of the page by its extension, ext.
func contentType(ext string) string {
	switch ext {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}
