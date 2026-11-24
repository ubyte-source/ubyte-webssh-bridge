package frontend

import "embed"

// Root is the directory of Files that holds the page.
const Root = "public"

//go:embed public
var files embed.FS

// Files returns the page: Root and every file under it, as the build embedded them.
func Files() embed.FS {
	return files
}
