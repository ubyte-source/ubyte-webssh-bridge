// Package frontend embeds the page in the binary: index.html, the favicon, the style
// sheets and the ES modules under public, the vendored xterm files included. They are
// plain static files with absolute paths, so a web server in front of the bridge can
// serve the same directory as it is.
package frontend
