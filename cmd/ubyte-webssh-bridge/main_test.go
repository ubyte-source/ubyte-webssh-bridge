package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// awaitBound bounds each wait of a test for the bridge.
const awaitBound = 10 * time.Second

// errLost is the failure of every write to lostOutput.
var errLost = errors.New("output lost")

// lostOutput is an output whose every write fails.
type lostOutput struct{}

func (lostOutput) Write([]byte) (int, error) { return 0, errLost }

// output keeps what a run writes, from any goroutine.
type output struct {
	mu   sync.Mutex
	text strings.Builder
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.text.Write(p)
	return len(p), nil
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text.String()
}

// await reports whether a record of msg is written within awaitBound.
func (o *output) await(msg string) bool {
	return waitUntil(func() bool { return len(recordsOf(o.String(), msg)) > 0 })
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

// pairFiles writes to a directory of t a self-signed certificate and its key as PEM
// files and returns their paths.
func pairFiles(t *testing.T) (cert, key string) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey error = %v, want nil", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bridge.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatalf("x509.CreateCertificate error = %v, want nil", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey error = %v, want nil", err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("os.OpenRoot error = %v, want nil", err)
	}
	defer closeRoot(t, root)
	for name, block := range map[string]*pem.Block{
		"certificate.crt": {Type: "CERTIFICATE", Bytes: der},
		"certificate.key": {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := root.WriteFile(name, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("root.WriteFile(%s) error = %v, want nil", name, err)
		}
	}
	return filepath.Join(root.Name(), "certificate.crt"), filepath.Join(root.Name(), "certificate.key")
}

func closeRoot(t *testing.T, root *os.Root) {
	t.Helper()
	if err := root.Close(); err != nil {
		t.Errorf("root.Close() error = %v, want nil", err)
	}
}

// setEnvironment empties every UWSB_ variable for t, then sets the listener address,
// a TLS pair of the test and env.
func setEnvironment(t *testing.T, address string, env map[string]string) {
	t.Helper()
	for _, pair := range os.Environ() {
		if name, _, _ := strings.Cut(pair, "="); strings.HasPrefix(name, "UWSB_") {
			t.Setenv(name, "")
		}
	}
	cert, key := pairFiles(t)
	t.Setenv("UWSB_SERVER_ADDRESS", address)
	t.Setenv("UWSB_SERVER_CERT", cert)
	t.Setenv("UWSB_SERVER_KEY", key)
	for name, v := range env {
		t.Setenv(name, v)
	}
}

// textOf returns the text of the attribute key of rec.
func textOf(rec map[string]any, key string) string {
	return fmt.Sprint(rec[key])
}

// loadConfig returns the configuration of the environment.
func loadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load([]string{}, io.Discard)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	return cfg
}

// TestRunWritesTheUsage runs -h: the golden usage on stderr, nothing on stdout, 0.
func TestRunWritesTheUsage(t *testing.T) {
	var stdout, stderr strings.Builder
	if got := run(t.Context(), []string{"-h"}, &stdout, &stderr); got != exitClean {
		t.Errorf("run(-h) = %d, want %d", got, exitClean)
	}
	golden := moduleText(t, "internal/config/testdata/ubyte-webssh-bridge-help.golden")
	if stderr.String() != golden || stdout.Len() != 0 {
		t.Errorf("run(-h) wrote stdout %q, stderr\n%s\nwant nothing and the golden usage", stdout.String(),
			stderr.String())
	}
}

// TestRunPrintsTheVersion runs -version: the version and the Go release on stdout, 0.
func TestRunPrintsTheVersion(t *testing.T) {
	var stdout, stderr strings.Builder
	got := run(t.Context(), []string{"-version"}, &stdout, &stderr)
	if want := "dev (go=" + runtime.Version() + ")\n"; got != exitClean || stdout.String() != want ||
		stderr.Len() != 0 {
		t.Errorf("run(-version) = %d, stdout %q, stderr %q, want %d and %q", got, stdout.String(),
			stderr.String(), exitClean, want)
	}
}

// TestWriteOutputReportsALostOutput writes to an output that fails: exitFailure.
func TestWriteOutputReportsALostOutput(t *testing.T) {
	if got := writeOutput(lostOutput{}, []byte("x"), exitClean); got != exitFailure {
		t.Errorf("writeOutput(a lost output) = %d, want %d", got, exitFailure)
	}
}

// TestRunExitsTwoOnARefusedConfiguration runs an unknown flag, which writes the usage
// beside the record, and a variable out of range, which writes the record alone: both
// exit 2.
func TestRunExitsTwoOnARefusedConfiguration(t *testing.T) {
	setEnvironment(t, "127.0.0.1:8443", nil)
	var stdout, stderr strings.Builder
	got := run(t.Context(), []string{"-health-enabled"}, &stdout, &stderr)
	recs := recordsOf(stderr.String(), "invalid configuration")
	if got != exitInvalid || stdout.Len() != 0 || len(recs) != 1 || recs[0]["level"] != "ERROR" ||
		!strings.HasPrefix(stderr.String(), "Usage of ubyte-webssh-bridge:\n") {
		t.Errorf("run(-health-enabled) = %d, stdout %q, stderr %q, want %d, the usage and the record", got,
			stdout.String(), stderr.String(), exitInvalid)
	}
	t.Setenv("UWSB_RATE_BURST", "0")
	stderr.Reset()
	got = run(t.Context(), []string{}, &stdout, &stderr)
	recs = recordsOf(stderr.String(), "invalid configuration")
	if got != exitInvalid || len(recs) != 1 || strings.Contains(stderr.String(), "Usage of") ||
		!strings.Contains(textOf(recs[0], "error"), "-rate-burst (UWSB_RATE_BURST)") {
		t.Errorf("run() with UWSB_RATE_BURST=0 = %d, stderr %q, want %d and the record alone", got,
			stderr.String(), exitInvalid)
	}
}

// TestRunProbesTheListenAddress runs -health against a listener the test opens, 0, and
// against a port nothing listens on, 1.
func TestRunProbesTheListenAddress(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer closeListener(t, ln)
	for address, want := range map[string]int{ln.Addr().String(): exitClean, refusedAddress: exitFailure} {
		setEnvironment(t, address, nil)
		var stdout, stderr strings.Builder
		if got := run(t.Context(), []string{"-health"}, &stdout, &stderr); got != want {
			t.Errorf("run(-health) on %s = %d, stdout %q, want %d", address, got, stdout.String(), want)
		}
	}
}

// TestRunProbesUnderTheContext runs -health against a listener the test opens under a
// canceled context: the probe ends with the context, 1.
func TestRunProbesUnderTheContext(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer closeListener(t, ln)
	setEnvironment(t, ln.Addr().String(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, stderr strings.Builder
	if got := run(ctx, []string{"-health"}, &stdout, &stderr); got != exitFailure {
		t.Errorf("run(-health) under a canceled context = %d, stdout %q, want %d", got, stdout.String(), exitFailure)
	}
}

// TestRunExitsOneOnAListenFailure runs on an address another listener holds: the
// record names it, and the run exits 1.
func TestRunExitsOneOnAListenFailure(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer closeListener(t, ln)
	setEnvironment(t, ln.Addr().String(), nil)
	var stdout, stderr strings.Builder
	got := run(t.Context(), []string{}, &stdout, &stderr)
	recs := recordsOf(stdout.String(), "listen failed")
	if got != exitFailure || len(recs) != 1 || recs[0]["address"] != ln.Addr().String() || recs[0]["error"] == nil {
		t.Errorf("run() on a held address = %d, records %q, want %d and listen failed", got, stdout.String(),
			exitFailure)
	}
}

// freeAddress returns a loopback address that nothing listens on: the test listens on
// a free port and closes it.
func freeAddress(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	closeListener(t, ln)
	return ln.Addr().String()
}

// TestRunServesUntilTheContextEnds runs on a free loopback port until the test
// cancels: the start record, the unread variable, serving, stopping, and 0.
func TestRunServesUntilTheContextEnds(t *testing.T) {
	address := freeAddress(t)
	setEnvironment(t, address, map[string]string{"UWSB_SESSION_IDLE_TIMEOUT": "30m"})
	ctx, cancel := context.WithCancel(t.Context())
	out := new(output)
	status := make(chan int, 1)
	go func() { status <- run(ctx, []string{}, out, out) }()
	if !out.await("serving") {
		t.Fatalf("no serving record within %v: %s", awaitBound, out.String())
	}
	cancel()
	if got := <-status; got != exitClean || !out.await("stopping") {
		t.Errorf("run() after the cancel = %d, records %s, want %d and stopping", got, out.String(), exitClean)
	}
	start := recordsOf(out.String(), "starting ubyte-webssh-bridge")
	unread := recordsOf(out.String(), "unread variable")
	if len(start) != 1 || start[0]["address"] != address || start[0]["version"] != "dev" || len(unread) != 1 ||
		unread[0]["name"] != "UWSB_SESSION_IDLE_TIMEOUT" || unread[0]["level"] != "WARN" {
		t.Errorf("records %s, want the start record and the unread variable", out.String())
	}
}

// TestLogStartNamesTheRoute logs the start of each route: the pinned one names its
// target and no per-host cap, the path one its per-host cap and no target.
func TestLogStartNamesTheRoute(t *testing.T) {
	for _, target := range []string{"192.0.2.10:22", ""} {
		setEnvironment(t, "127.0.0.1:8443", map[string]string{"UWSB_SSH_TARGET": target})
		cfg := loadConfig(t)
		var out strings.Builder
		logStart(t.Context(), newLogger(&out, slog.LevelInfo), cfg)
		recs := recordsOf(out.String(), "starting ubyte-webssh-bridge")
		want := map[string]any{"route": routePath, "target": nil, "conn_max_per_host": float64(10)}
		if target != "" {
			want = map[string]any{"route": routePinned, "target": target, "conn_max_per_host": nil}
		}
		if len(recs) != 1 || recs[0]["certificate"] != cfg.Server.CertFile ||
			recs[0]["certificate_key"] != cfg.Server.KeyFile || recs[0]["conn_max_total"] != float64(1000) {
			t.Fatalf("records %q, want one start record with the TLS files and the total cap", out.String())
		}
		for key, value := range want {
			if recs[0][key] != value {
				t.Errorf("target %q: %s = %v, want %v", target, key, recs[0][key], value)
			}
		}
	}
}

// TestStoppedMapsTheEndToTheExitStatus maps nil to 0 and a failure to 1, logged.
func TestStoppedMapsTheEndToTheExitStatus(t *testing.T) {
	var out strings.Builder
	log := newLogger(&out, slog.LevelInfo)
	if got := stopped(t.Context(), log, nil); got != exitClean || out.Len() != 0 {
		t.Errorf("stopped(nil) = %d, records %q, want %d and none", got, out.String(), exitClean)
	}
	if got := stopped(t.Context(), log, errLost); got != exitFailure {
		t.Errorf("stopped(a failure) = %d, want %d", got, exitFailure)
	}
	recs := recordsOf(out.String(), "serve failed")
	if len(recs) != 1 || recs[0]["error"] != errLost.Error() || recs[0]["level"] != "ERROR" {
		t.Errorf("records %q, want serve failed with the error", out.String())
	}
}

// TestLevelOfWritesDebugWhenAsked writes a debug record through the logger of each
// level: only the debug one keeps it.
func TestLevelOfWritesDebugWhenAsked(t *testing.T) {
	for debug, want := range map[bool]int{false: 0, true: 1} {
		var out strings.Builder
		newLogger(&out, levelOf(&config.ServerConfig{Debug: debug})).LogAttrs(t.Context(), slog.LevelDebug, "kept")
		if got := len(recordsOf(out.String(), "kept")); got != want {
			t.Errorf("newLogger(debug %v) wrote %d debug records, want %d", debug, got, want)
		}
	}
}

// childCommand returns the test binary as a command that runs main with args and
// writes its counters into the folder of the parent's, and the output it writes.
func childCommand(t *testing.T, args ...string) (child *exec.Cmd, out *output) {
	t.Helper()
	child = exec.CommandContext(t.Context(), os.Args[0], args...) //nolint:gosec // the test binary runs itself
	child.Env = append(os.Environ(), runMainEnv+"=1")
	if dir := flag.Lookup("test.gocoverdir"); dir != nil && dir.Value.String() != "" {
		child.Env = append(child.Env, "GOCOVERDIR="+dir.Value.String())
	}
	out = new(output)
	child.Stdout, child.Stderr = out, out
	return child, out
}

// TestMainStopsOnSignal runs main in a child process: SIGTERM stops it, with the
// signal as the cause, and it exits 0.
func TestMainStopsOnSignal(t *testing.T) {
	setEnvironment(t, freeAddress(t), nil)
	child, out := childCommand(t)
	if err := child.Start(); err != nil {
		t.Fatalf("start main = %v, want nil", err)
	}
	if !out.await("serving") {
		t.Errorf("main wrote %q, want a serving record", out.String())
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal(SIGTERM) = %v, want nil", err)
	}
	err := child.Wait()
	stopping := recordsOf(out.String(), "stopping")
	if err != nil || len(stopping) != 1 || stopping[0]["cause"] != "terminated signal received" {
		t.Fatalf("main after SIGTERM = %v, output %q; want exit 0 and a stopping record of SIGTERM", err,
			out.String())
	}
}

// TestMainExitsWithTheStatusOfRun runs main in a child process: 0 for -version, 2 for
// a configuration to fix.
func TestMainExitsWithTheStatusOfRun(t *testing.T) {
	setEnvironment(t, "0.0.0.0:8443", nil)
	for _, tc := range []struct {
		args []string
		want int
	}{
		{args: []string{"-version"}, want: exitClean},
		{want: exitInvalid},
	} {
		child, out := childCommand(t, tc.args...)
		err := child.Run()
		code := 0
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		}
		if code != tc.want {
			t.Errorf("main %q = %v, output %q; want exit %d", tc.args, err, out.String(), tc.want)
		}
	}
}

// limitsColumns is the count of the columns of SECURITY's limits table.
const limitsColumns = 5

// TestMainSecurityLimitsTable pins each row of SECURITY's limits table: the tests it
// names exist, and a row of variables opens its value with the default of the first;
// each constant named as a limit holds a row's value or is a non-limit.
func TestMainSecurityLimitsTable(t *testing.T) {
	rows := tableRows(markdownSection(t, "SECURITY.md", "## Known limits"))
	if len(rows) == 0 {
		t.Fatal("SECURITY.md's limits table has 0 rows, want one per bound")
	}
	defaults, tests := flagDefaults(t), declaredTests(t)
	for _, row := range rows {
		checkLimitsRow(t, row, defaults, tests)
	}
	consts := constValues(t)
	checkCandidates(t, consts, pinnedLimits(t, rows, consts))
}

// checkLimitsRow fails t unless row, a row of SECURITY's limits table, names tests that
// tests holds and opens its value with the default of its first variable.
func checkLimitsRow(t *testing.T, row []string, defaults map[string]string, tests map[string]bool) {
	t.Helper()
	if len(row) != limitsColumns {
		t.Errorf("limits row %q, want %d cells", row, limitsColumns)
		return
	}
	pinned := codeSpans(row[limitsColumns-1])
	if len(pinned) == 0 {
		t.Errorf("limits row %q names no test in its Pinned by cell, want one at least", row[0])
	}
	for _, test := range pinned {
		if !tests[test] {
			t.Errorf("limits row %q names %q, which no Go or node test declares", row[0], test)
		}
	}
	spans := codeSpans(row[1])
	names := slices.DeleteFunc(slices.Clone(spans), func(s string) bool { return !strings.HasPrefix(s, "UWSB_") })
	if len(names) == 0 {
		return
	}
	if def, read := defaults[names[0]]; !read || len(spans) == 0 || !sameValue(spans[0], def) {
		t.Errorf("limits row %q opens its value with %q, want the default %q of %s", row[0], spans, def, names[0])
	}
}

// moduleText returns the file at path, from the module root.
func moduleText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s = %v, want nil", path, err)
	}
	return string(b)
}

// markdownSection returns the lines under heading in the Markdown file, a path from the
// module root, up to the next heading of its level or above outside a fenced block.
func markdownSection(t *testing.T, file, heading string) []string {
	t.Helper()
	level := strings.IndexFunc(heading, func(r rune) bool { return r != '#' })
	var lines []string
	found, fenced := false, false
	for line := range strings.Lines(moduleText(t, file)) {
		line = strings.TrimSuffix(line, "\n")
		switch {
		case !found:
			found = line == heading
			continue
		case strings.HasPrefix(line, "```"):
			fenced = !fenced
		case !fenced && strings.HasPrefix(line, "#") &&
			strings.IndexFunc(line, func(r rune) bool { return r != '#' }) <= level:
			return lines
		}
		lines = append(lines, line)
	}
	if !found {
		t.Fatalf("%s holds no heading %q, want one", file, heading)
	}
	return lines
}

// tableRows returns the trimmed cells of each row of the tables in lines, but the
// header rows and the delimiter rows.
func tableRows(lines []string) [][]string {
	var rows [][]string
	for i, line := range lines {
		header := i+1 < len(lines) && strings.HasPrefix(lines[i+1], "|-")
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|-") || header {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for j := range cells {
			cells[j] = strings.TrimSpace(cells[j])
		}
		rows = append(rows, cells)
	}
	return rows
}

// codeSpan matches a code span of Markdown text.
var codeSpan = regexp.MustCompile("`([^`]*)`")

// codeSpans returns the text of each code span of the Markdown text s.
func codeSpans(s string) []string {
	matches := codeSpan.FindAllStringSubmatch(s, -1)
	spans := make([]string, 0, len(matches))
	for _, m := range matches {
		spans = append(spans, m[1])
	}
	return spans
}

// flagDefaults returns, for each variable, the default the usage prints for its flag,
// or the zero text of the flag's type when the usage prints none.
func flagDefaults(t *testing.T) map[string]string {
	t.Helper()
	zero := map[string]string{"int": "0", "duration": "0s"}
	printed := regexp.MustCompile(`\(default (.+)\)\n$`)
	byFlag := make(map[string]string)
	name := ""
	for line := range strings.Lines(moduleText(t, "internal/config/testdata/ubyte-webssh-bridge-help.golden")) {
		if rest, ok := strings.CutPrefix(line, "  -"); ok {
			var kind string
			name, kind, _ = strings.Cut(strings.TrimSpace(rest), " ")
			byFlag[name] = zero[kind]
		} else if m := printed.FindStringSubmatch(line); m != nil {
			byFlag[name] = m[1]
		}
	}
	defaults := make(map[string]string)
	for line := range strings.Lines(moduleText(t, "internal/config/testdata/variables.golden")) {
		if fields := strings.Fields(line); len(fields) == 2 {
			defaults[fields[0]] = byFlag[strings.TrimPrefix(fields[1], "-")]
		}
	}
	return defaults
}

// sameValue reports whether the texts a and b hold one value: the same duration, or
// the same text once quotes are trimmed.
func sameValue(a, b string) bool {
	da, errA := time.ParseDuration(a)
	db, errB := time.ParseDuration(b)
	if errA == nil && errB == nil {
		return da == db
	}
	return strings.Trim(a, `"`) == strings.Trim(b, `"`)
}

// The names a test of the module declares: a Go test, fuzz target or benchmark, and a
// node test.
var (
	goTest   = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)\w*)\(`)
	nodeTest = regexp.MustCompile("\\btest\\(\\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)")
)

// declaredTests returns the name of every Go test of the module's test files and of
// every node test of frontend/test.
func declaredTests(t *testing.T) map[string]bool {
	t.Helper()
	tests := map[string]bool{}
	for _, file := range moduleFiles(t, func(p string) bool {
		return strings.HasSuffix(p, "_test.go") ||
			strings.HasPrefix(p, "frontend/test/") && strings.HasSuffix(p, ".test.js")
	}) {
		text := moduleText(t, file)
		for _, m := range goTest.FindAllStringSubmatch(text, -1) {
			tests[m[1]] = true
		}
		for _, m := range nodeTest.FindAllStringSubmatch(text, -1) {
			tests[m[1]+m[2]+m[3]] = true
		}
	}
	return tests
}

// moduleFiles returns, sorted, the path from the module root of every file of the
// module that keep holds, outside .git and node_modules.
func moduleFiles(t *testing.T, keep func(path string) bool) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules"):
			return filepath.SkipDir
		case d.IsDir():
			return nil
		}
		if rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator))); keep(rel) {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the module = %v, want nil", err)
	}
	slices.Sort(files)
	return files
}

// limitName matches the names that mark a constant as a limit.
var limitName = regexp.MustCompile(`(?i)limit|timeout|max|bound`)

// limitRow is a constant that holds the value of a row of SECURITY's limits table, by
// its directory and its name, and the Limit of that row.
type limitRow struct {
	constant, limit string
}

// limitRows returns the constants that hold the value of a row of SECURITY's limits
// table.
func limitRows() []limitRow {
	return []limitRow{
		{"internal/config.defaultConnMaxTotal", "Concurrent sessions of the process"},
		{"internal/config.defaultConnMaxPerHost", "Concurrent sessions to one target (path route)"},
		{"internal/config.defaultServerShutdownTimeout", "The stop"},
		{"internal/config.defaultSSHConnectTimeout", "TCP connect to the target"},
		{"internal/config.defaultSSHLoginTimeout",
			"The login and the opening of the shell, the user's answers included"},
		{"internal/config.defaultWSHandshakeTimeout", "Request headers and the connect message"},
		{"internal/config.maxTrustedProxies", "Trusted proxy entries"},
		{"internal/server.maxClients", "Client addresses the rate bound tracks"},
		{"internal/server.writeTimeout", "A file response"},
		{"internal/server.idleTimeout", "An idle HTTP connection"},
		{"internal/protocol.MaxMessageBytes", "One message from the page"},
		{"internal/protocol.maxBannerBytes", "Bytes of a banner shown"},
		{"internal/protocol.maxSignalBytes", "Bytes of an exit signal name sent"},
		{"internal/protocol.maxPromptBytes", "Bytes of a prompt; of a name or instruction shown"},
		{"internal/protocol.maxTextBytes", "Bytes of a prompt; of a name or instruction shown"},
		{"internal/protocol.maxDepth", "JSON nesting of a page message"},
		{"internal/protocol.maxUserBytes", "User name, password, one answer"},
		{"internal/protocol.maxPasswordBytes", "User name, password, one answer"},
		{"internal/protocol.maxAnswerBytes", "User name, password, one answer"},
		{"internal/protocol.maxAnswers", "Answers of one message"},
		{"internal/protocol.maxBase64Chars", "Public key, signature (base64)"},
		{"internal/protocol.maxCells", "Terminal columns and rows"},
		{"internal/sshclient.maxRounds", "Keyboard-interactive rounds of one login"},
		{"internal/sshclient.maxPrompts", "Prompts of a round"},
		{"internal/sshclient.maxRSABits", "RSA modulus of a key the page loads"},
		{"internal/session.pongTimeout", "Pong after a ping"},
		{"internal/session.outputTimeout", "A frame the page does not take"},
		{"internal/session.inputTimeout", "A write to the shell the device does not take"},
	}
}

// The reasons of the non-limits that bound a setting: its range, which README's Range
// column states, or its grammar.
const (
	rangeBound   = "a bound of a README Range column, pinned by the configuration's range tests"
	grammarBound = "a bound of the target grammar, pinned by the configuration's grammar tests"
)

// nonLimits returns the constants named as a limit that hold the value of no row of
// SECURITY's limits table, each with the reason.
func nonLimits() map[string]string {
	return map[string]string{
		"internal/config.maxConnect":    rangeBound,
		"internal/config.maxWait":       rangeBound,
		"internal/config.maxSessions":   rangeBound,
		"internal/config.maxBurst":      rangeBound,
		"internal/config.maxNameBytes":  grammarBound,
		"internal/config.maxLabelBytes": grammarBound,
		"internal/server.maxHeaderBytes": "net/http's MaxHeaderBytes, whose row states 20480: the bound and the " +
			"4096 bytes net/http reads past it",
		"cmd/ubyte-webssh-bridge.healthTimeout": "the probe's own deadline, under the HEALTHCHECK timeout",
		"internal/protocol.CloseLoginTimeout":   "a close code, the number of a way a session ends",
		"internal/protocol.CloseRateLimited":    "a close code, the number of a way a session ends",
	}
}

// productionFiles returns every production Go file of the module, parsed, keyed by its
// path from the module root.
func productionFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	files := map[string]*ast.File{}
	for _, file := range moduleFiles(t, func(p string) bool {
		return strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") && !strings.Contains(p, "testdata/")
	}) {
		f, err := parser.ParseFile(token.NewFileSet(), file, moduleText(t, file), parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s = %v, want nil", file, err)
		}
		files[file] = f
	}
	return files
}

// constValues returns the value, as written, of every package-level constant of the
// production files whose name marks a limit, keyed by its directory and its name, such
// as internal/x.name.
func constValues(t *testing.T) map[string]string {
	t.Helper()
	values := map[string]string{}
	for file, f := range productionFiles(t) {
		for _, decl := range f.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.CONST {
				addConsts(values, filepath.ToSlash(filepath.Dir(file)), gen)
			}
		}
	}
	return values
}

// addConsts adds to values the constants of decl, a const declaration of the package at
// dir, whose name marks a limit; a constant without a value repeats the one above.
func addConsts(values map[string]string, dir string, decl *ast.GenDecl) {
	var written []ast.Expr
	for _, spec := range decl.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Values) > 0 {
			written = vs.Values
		}
		for i, value := range written {
			if limitName.MatchString(vs.Names[i].Name) {
				values[dir+"."+vs.Names[i].Name] = types.ExprString(value)
			}
		}
	}
}

// pinnedLimits returns the constants of limitRows, failing t on one that is no
// constant of consts, whose Limit is no row of rows, or whose value is none of that
// row's values.
func pinnedLimits(t *testing.T, rows [][]string, consts map[string]string) map[string]bool {
	t.Helper()
	values := map[string]string{}
	for _, row := range rows {
		if len(row) == limitsColumns {
			values[row[0]] = row[1]
		}
	}
	pinned := map[string]bool{}
	for _, row := range limitRows() {
		key, limit := row.constant, row.limit
		pinned[key] = true
		value, listed := values[limit]
		written, declared := consts[key]
		if !listed || !declared {
			t.Errorf("limitRows gives %s the row %q: constant found %v, row found %v; want both", key, limit,
				declared, listed)
			continue
		}
		if n := constNumber(t, key, written); !slices.ContainsFunc(codeSpans(value), func(s string) bool {
			return spanNumber(s) == n
		}) {
			t.Errorf("constant %s = %d, want a value of %q in SECURITY's limits table", key, n, limit)
		}
	}
	return pinned
}

// spanNumber returns the integer a code span of a Value cell writes, a duration in
// nanoseconds, or -1 for another text.
func spanNumber(span string) int64 {
	if d, err := time.ParseDuration(span); err == nil && strings.ContainsAny(span, "hms") {
		return int64(d)
	}
	n, err := strconv.ParseInt(span, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// constNumber returns the integer of written, the value of the constant key as the code
// writes it, an expression of integer literals and units of time.
func constNumber(t *testing.T, key, written string) int64 {
	t.Helper()
	units := strings.NewReplacer("time.Nanosecond", "1", "time.Microsecond", "1000", "time.Millisecond", "1000000",
		"time.Second", "1000000000", "time.Minute", "60000000000", "time.Hour", "3600000000000")
	tv, err := types.Eval(token.NewFileSet(), nil, token.NoPos, units.Replace(written))
	if err != nil {
		t.Fatalf("constant %s = %s: %v, want an integer expression of literals", key, written, err)
	}
	n, exact := constant.Int64Val(constant.ToInt(tv.Value))
	if !exact {
		t.Fatalf("constant %s = %s, want an integer of 64 bits", key, written)
	}
	return n
}

// checkCandidates fails t on a constant of consts that both pinned and the non-limit
// list hold, or neither, and on a non-limit that names no such constant.
func checkCandidates(t *testing.T, consts map[string]string, pinned map[string]bool) {
	t.Helper()
	others := nonLimits()
	for key := range consts {
		if _, other := others[key]; pinned[key] == other {
			t.Errorf("constant %s is named as a limit: limitRows holds it %v, nonLimits %v; want it in one of them",
				key, pinned[key], other)
		}
		delete(others, key)
	}
	for key := range others {
		t.Errorf("non-limit %s names no constant named as a limit, want one", key)
	}
}

// imageSetsNoVariable is README's sentence about the variables of the image.
const imageSetsNoVariable = "The image sets no variable."

// TestMainImageSetsNoVariable finds no ENV instruction in Dockerfile, and README's
// sentence that the image sets no variable, however its lines wrap.
func TestMainImageSetsNoVariable(t *testing.T) {
	for i, line := range strings.Split(moduleText(t, "Dockerfile"), "\n") {
		if words := strings.Fields(line); len(words) > 0 && strings.EqualFold(words[0], "ENV") {
			t.Errorf("Dockerfile:%d: %s, want no ENV instruction", i+1, line)
		}
	}
	readme := strings.Join(strings.Fields(moduleText(t, "README.md")), " ")
	if !strings.Contains(readme, imageSetsNoVariable) {
		t.Errorf("README.md lacks %q, want it", imageSetsNoVariable)
	}
}

// TestMainDocumentsTheExitStatuses pins README's status table to the exit statuses of
// the command, in order.
func TestMainDocumentsTheExitStatuses(t *testing.T) {
	rows := tableRows(markdownSection(t, "README.md", "## Commands"))
	documented := make([]string, 0, len(rows))
	for _, row := range rows {
		documented = append(documented, row[0])
	}
	want := []string{strconv.Itoa(exitClean), strconv.Itoa(exitFailure), strconv.Itoa(exitInvalid)}
	if !slices.Equal(documented, want) {
		t.Fatalf("README's status table lists %q, want %q", documented, want)
	}
}

// writtenRecords returns, sorted, the message of every record of the production files.
func writtenRecords(t *testing.T) []string {
	t.Helper()
	var messages []string
	for _, f := range productionFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if message, isRecord := recordOf(t, call); isRecord {
					messages = append(messages, message)
				}
			}
			return true
		})
	}
	slices.Sort(messages)
	return slices.Compact(messages)
}

// recordOf returns the message of call when it is a LogAttrs call, which passes the
// message as a string literal after the context and the level.
func recordOf(t *testing.T, call *ast.CallExpr) (string, bool) {
	t.Helper()
	if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "LogAttrs" {
		return "", false
	}
	lit, ok := call.Args[2].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		t.Fatalf("a LogAttrs call writes %s, want a string literal", types.ExprString(call.Args[2]))
	}
	message, err := strconv.Unquote(lit.Value)
	if err != nil {
		t.Fatalf("unquote %s = %v, want nil", lit.Value, err)
	}
	return message, true
}

// TestMainDocumentsEveryRecord pins README's Logs table to the records the production
// files write, one row per message.
func TestMainDocumentsEveryRecord(t *testing.T) {
	rows := tableRows(markdownSection(t, "README.md", "## Logs"))
	documented := make([]string, 0, len(rows))
	for _, row := range rows {
		documented = append(documented, codeSpans(row[1])...)
	}
	slices.Sort(documented)
	if written := writtenRecords(t); !slices.Equal(documented, written) {
		t.Errorf("README's Logs table lists %q, want the records the code writes, %q", documented, written)
	}
}
