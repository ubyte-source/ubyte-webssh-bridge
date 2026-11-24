package frontend

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"testing"
)

// treeOf returns, sorted, the path of every regular file of fsys under Root.
func treeOf(t *testing.T, fsys fs.FS) []string {
	t.Helper()
	var found []string
	err := fs.WalkDir(fsys, Root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			found = append(found, p)
		}
		return err
	})
	if err != nil {
		t.Fatalf("fs.WalkDir(%s) = %v, want nil", Root, err)
	}
	slices.Sort(found)
	return found
}

// TestFilesHoldsThePublicTree walks Files and the directory on disk: they hold the same
// files with the same bytes, index.html among them.
func TestFilesHoldsThePublicTree(t *testing.T) {
	embedded, disk := Files(), os.DirFS(".")
	got, want := treeOf(t, embedded), treeOf(t, disk)
	if !slices.Equal(got, want) || !slices.Contains(got, path.Join(Root, "index.html")) {
		t.Fatalf("Files() holds %q, want the files on disk %q, index.html among them", got, want)
	}
	for _, name := range got {
		a, errA := fs.ReadFile(embedded, name)
		b, errB := fs.ReadFile(disk, name)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Errorf("%s: embedded %d bytes (%v), on disk %d bytes (%v), want the same bytes", name, len(a), errA,
				len(b), errB)
		}
	}
}

// The markup that would run or style the page from index.html itself: a script tag
// without src, a style attribute and an event attribute.
var (
	scriptTag      = regexp.MustCompile(`(?i)<script\b[^>]*>`)
	scriptSource   = regexp.MustCompile(`(?i)\ssrc\s*=`)
	inlineHandlers = regexp.MustCompile(`(?i)\s(style|on[a-z]+)\s*=`)
)

// inlineCode returns the inline code of markup: each script tag without src, and each
// style or event attribute.
func inlineCode(markup string) []string {
	var found []string
	for _, tag := range scriptTag.FindAllString(markup, -1) {
		if !scriptSource.MatchString(tag) {
			found = append(found, tag)
		}
	}
	return append(found, inlineHandlers.FindAllString(markup, -1)...)
}

// TestFilesIndexRunsNoInlineCode reads the embedded index.html: every script has a
// src, and no element carries a style or an event attribute.
func TestFilesIndexRunsNoInlineCode(t *testing.T) {
	index, err := fs.ReadFile(Files(), path.Join(Root, "index.html"))
	if err != nil {
		t.Fatalf("read index.html = %v, want nil", err)
	}
	if found := inlineCode(string(index)); len(found) > 0 {
		t.Errorf("index.html holds %q, want no inline script, style or event attribute", found)
	}
	for _, sample := range []string{
		`<script>alert(1)</script>`, `<script type="module">x()</script>`, `<div style="color:red">`,
		`<body onload="x()">`, `<img src=x onerror=y>`,
	} {
		if len(inlineCode(sample)) != 1 {
			t.Errorf("inlineCode(%q) = %q, want one finding", sample, inlineCode(sample))
		}
	}
	if sample := `<script type="module" src="/javascript/main.js"></script>`; len(inlineCode(sample)) != 0 {
		t.Errorf("inlineCode(%q) = %q, want a script with src passed", sample, inlineCode(sample))
	}
}
