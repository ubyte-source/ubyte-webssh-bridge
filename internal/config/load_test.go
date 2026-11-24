package config

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// documentedDefaults returns the configuration of the documented defaults, as
// literals, with the listen address and the files of env, a baseEnvironment.
func documentedDefaults(env map[string]string) Config {
	return Config{
		Server: ServerConfig{
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
			Address:        env[envAddress], CertFile: env[envCert], KeyFile: env[envKey],
			ShutdownTimeout: 30 * time.Second,
		},
		Conn: ConnConfig{MaxTotal: 1000, MaxPerHost: 10},
		Rate: RateConfig{Burst: 10, Interval: 2 * time.Second},
		SSH:  SSHConfig{ConnectTimeout: 10 * time.Second, LoginTimeout: 120 * time.Second},
		WS:   WSConfig{HandshakeTimeout: 10 * time.Second},
	}
}

// checkConfig fails t unless err is nil, cfg holds a loaded certificate, and cfg
// beside it is want.
func checkConfig(t *testing.T, what string, cfg *Config, err error, want *Config) {
	t.Helper()
	if err != nil || cfg == nil || len(cfg.Server.Certificate.Certificate) != 1 {
		t.Fatalf("%s: Load() = %+v, %v, want a Config with its certificate and nil", what, cfg, err)
	}
	got := *cfg
	got.Server.Certificate = want.Server.Certificate
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("%s: Load() =\n%+v\nwant\n%+v", what, got, *want)
	}
}

// TestLoadDefaultsEqualTheDocumentedValues loads baseEnvironment alone: every other
// setting holds its documented default.
func TestLoadDefaultsEqualTheDocumentedValues(t *testing.T) {
	env := baseEnvironment(t)
	cfg, usage, err := loadWith(t, env, []string{})
	want := documentedDefaults(env)
	checkConfig(t, "defaults", cfg, err, &want)
	if usage != "" {
		t.Errorf("Load() wrote the usage %q, want none", usage)
	}
}

// settingTexts returns, for every setting but the listen address, the TLS files and
// the target, two texts distinct from each other and, but for the bool, from the
// default.
func settingTexts() [][3]string {
	return [][3]string{
		{"UWSB_CONN_MAX_PER_HOST", "5", "7"},
		{"UWSB_CONN_MAX_TOTAL", "500", "700"},
		{"UWSB_RATE_BURST", "3", "4"},
		{"UWSB_RATE_INTERVAL", "3s", "4s"},
		{"UWSB_SERVER_DEBUG", "true", "false"},
		{"UWSB_SERVER_SHUTDOWN_TIMEOUT", "31s", "32s"},
		{"UWSB_SERVER_TRUSTED_PROXIES", "192.0.2.0/24, 198.51.100.7", "2001:db8::/32"},
		{"UWSB_SSH_CONNECT_TIMEOUT", "11s", "12s"},
		{"UWSB_SSH_LOGIN_TIMEOUT", "121s", "2m2s"},
		{"UWSB_WS_HANDSHAKE_TIMEOUT", "11s", "12s"},
	}
}

// columnTexts returns the column (1 or 2) of settingTexts beside the variables of
// base.
func columnTexts(column int, base map[string]string) map[string]string {
	out := maps.Clone(base)
	for _, row := range settingTexts() {
		out[row[0]] = row[column]
	}
	return out
}

// configA returns the Config column 1 of settingTexts gives over env, a
// baseEnvironment.
func configA(env map[string]string) Config {
	c := documentedDefaults(env)
	c.Conn = ConnConfig{MaxTotal: 500, MaxPerHost: 5}
	c.Rate = RateConfig{Burst: 3, Interval: 3 * time.Second}
	c.Server.Debug, c.Server.ShutdownTimeout = true, 31*time.Second
	c.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.7/32")}
	c.SSH.ConnectTimeout, c.SSH.LoginTimeout = 11*time.Second, 121*time.Second
	c.WS.HandshakeTimeout = 11 * time.Second
	return c
}

// configB returns the Config column 2 of settingTexts gives over env, a
// baseEnvironment: configA with each of its settings changed.
func configB(env map[string]string) Config {
	c := configA(env)
	c.Conn = ConnConfig{MaxTotal: 700, MaxPerHost: 7}
	c.Rate = RateConfig{Burst: 4, Interval: 4 * time.Second}
	c.Server.Debug, c.Server.ShutdownTimeout = false, 32*time.Second
	c.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	c.SSH.ConnectTimeout, c.SSH.LoginTimeout = 12*time.Second, 122*time.Second
	c.WS.HandshakeTimeout = 12 * time.Second
	return c
}

// asFlags returns texts, keyed by variable, as flag arguments in name order.
func asFlags(texts map[string]string) []string {
	args := make([]string, 0, len(texts))
	for _, s := range newTable() {
		if text, ok := texts[s.env]; ok {
			args = append(args, flagOf(s.env)+"="+text)
		}
	}
	return args
}

// TestLoadReadsEverySettingFromItsVariable sets every setting through its variable and
// requires the whole Config.
func TestLoadReadsEverySettingFromItsVariable(t *testing.T) {
	env := baseEnvironment(t)
	cfg, _, err := loadWith(t, columnTexts(1, env), []string{})
	want := configA(env)
	checkConfig(t, "variables", cfg, err, &want)
}

// TestLoadReadsEverySettingFromItsFlag sets every setting through its flag and
// requires the whole Config.
func TestLoadReadsEverySettingFromItsFlag(t *testing.T) {
	env := baseEnvironment(t)
	cfg, _, err := loadWith(t, nil, asFlags(columnTexts(2, env)))
	want := configB(env)
	checkConfig(t, "flags", cfg, err, &want)
}

// TestLoadFlagWinsOverTheVariable sets every setting through its variable and, with
// another value, through its flag: the flags' Config wins, -server-debug=false over
// UWSB_SERVER_DEBUG=true included.
func TestLoadFlagWinsOverTheVariable(t *testing.T) {
	envBase, flagBase := baseEnvironment(t), baseEnvironment(t)
	flagBase[envAddress] = "[::1]:10443"
	cfg, _, err := loadWith(t, columnTexts(1, envBase), asFlags(columnTexts(2, flagBase)))
	want := configB(flagBase)
	checkConfig(t, "variables and flags", cfg, err, &want)
}

// TestLoadBoolFlagAloneIsTrue gives -server-debug without a value over
// UWSB_SERVER_DEBUG=false: Debug is true.
func TestLoadBoolFlagAloneIsTrue(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_SERVER_DEBUG"] = "false"
	cfg, _, err := loadWith(t, env, []string{"-server-debug"})
	want := documentedDefaults(env)
	want.Server.Debug = true
	checkConfig(t, "-server-debug", cfg, err, &want)
}

// TestLoadEmptyValueIsUnset requires an empty variable and an empty flag to leave the
// setting as the layer below set it: the default, or the variable's value under an
// empty flag.
func TestLoadEmptyValueIsUnset(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_RATE_BURST"] = ""
	env["UWSB_SERVER_TRUSTED_PROXIES"] = ""
	cfg, _, err := loadWith(t, env, []string{"-ssh-target=", "-ws-handshake-timeout", ""})
	want := documentedDefaults(env)
	checkConfig(t, "empty variables and flags", cfg, err, &want)
	env["UWSB_RATE_BURST"] = "3"
	cfg, _, err = loadWith(t, env, []string{"-rate-burst="})
	want.Rate.Burst = 3
	checkConfig(t, "-rate-burst= over the variable's 3", cfg, err, &want)
}

// TestLoadReadsTheListWhole sets the trusted proxies through the variable and through
// the flag: each value is the whole list, never added to the one below.
func TestLoadReadsTheListWhole(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_SERVER_TRUSTED_PROXIES"] = "192.0.2.1"
	cfg, _, err := loadWith(t, env, []string{})
	want := documentedDefaults(env)
	want.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	checkConfig(t, "the variable", cfg, err, &want)
	cfg, _, err = loadWith(t, env, []string{"-server-trusted-proxies=198.51.100.0/24"})
	want.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	checkConfig(t, "the flag over the variable", cfg, err, &want)
}

// TestLoaderSetKeepsTheLayerBelow reads a valid value and then values that do not
// parse or leave the range: each is a problem of the setting, and the field keeps the
// valid value.
func TestLoaderSetKeepsTheLayerBelow(t *testing.T) {
	c := &Config{}
	l := newLoader(c)
	s := l.setting(&c.Conn.MaxTotal)
	l.set(s, "5")
	if s.failed || c.Conn.MaxTotal != 5 {
		t.Fatalf("set(5) = failed %v, MaxTotal %d, want 5 read", s.failed, c.Conn.MaxTotal)
	}
	for _, raw := range []string{"five", "0", "100001"} {
		l.set(s, raw)
		if !s.failed || c.Conn.MaxTotal != 5 {
			t.Errorf("set(%s) = failed %v, MaxTotal %d, want a fault and 5 kept", raw, s.failed, c.Conn.MaxTotal)
		}
	}
	if got := len(l.problems); got != 3 {
		t.Errorf("problems = %d, want 3: %v", got, l.problems)
	}
}

// TestLoadRefusesMalformedValues gives each kind a text it cannot read, through the
// variable and through the flag: each problem names the flag and the variable and
// quotes the text.
func TestLoadRefusesMalformedValues(t *testing.T) {
	base := baseEnvironment(t)
	for _, tc := range []struct {
		rule      error
		env, text string
		want      string
	}{
		{errNotInteger, "UWSB_RATE_BURST", "2O", `"2O" is not a base 10 integer`},
		{errNotInteger, "UWSB_RATE_BURST", "0x1F", `"0x1F" is not a base 10 integer`},
		{errNotInteger, "UWSB_RATE_BURST", " 10", `" 10" is not a base 10 integer`},
		{errNotInteger, "UWSB_CONN_MAX_TOTAL", "99999999999999999999",
			`"99999999999999999999" is not a base 10 integer`},
		{errNotDuration, "UWSB_RATE_INTERVAL", "5", `"5" is not a duration`},
		{errNotBool, "UWSB_SERVER_DEBUG", "yes", `"yes" is not a bool`},
		{errOutOfRange, "UWSB_SSH_CONNECT_TIMEOUT", "6m", `6m0s is outside 100ms-5m0s`},
		{errOutOfRange, "UWSB_RATE_BURST", "10001", `10001 is outside 1-10000`},
		{errListenAddress, envAddress, "localhost:8443",
			`"localhost:8443" is not host:port with an IP or no host and a port from 1 to 65535`},
		{ErrInvalidTarget, envTarget, "device.example.test", `"device.example.test" is an invalid target`},
	} {
		env := maps.Clone(base)
		env[tc.env] = tc.text
		_, _, err := loadWith(t, env, []string{})
		names := namesOf(tc.env)
		checkProblems(t, tc.env+"="+tc.text, err, wantProblem{tc.rule, names})
		if err == nil || !strings.Contains(err.Error(), names+": "+tc.want) {
			t.Errorf("%s=%s: Load() error = %v, want %q", tc.env, tc.text, err, names+": "+tc.want)
		}
		arg := flagOf(tc.env) + "=" + tc.text
		if _, _, err := loadWith(t, base, []string{arg}); !hasProblem(err, names, tc.rule) {
			t.Errorf("%s: Load() error = %v, want a problem of %s wrapping %v", arg, err, names, tc.rule)
		}
	}
	if _, _, err := loadWith(t, base, []string{"-version=maybe"}); !hasProblem(err, "-version", errNotBool) {
		t.Errorf("-version=maybe: Load() error = %v, want a problem of -version wrapping %v", err, errNotBool)
	}
	cfg, _, err := loadWith(t, base, []string{"-rate-burst=010"})
	if err != nil || cfg.Rate.Burst != 10 {
		t.Errorf("-rate-burst=010: Load() = %v, %v, want Burst 10 in base 10", cfg, err)
	}
}

// TestLoadRefusesExtraArguments requires an argument that is not a flag, an unknown
// flag and a flag without its value to stop the boot naming the argument's position,
// the usage written for a flag the line cannot read.
func TestLoadRefusesExtraArguments(t *testing.T) {
	base := baseEnvironment(t)
	for _, tc := range []struct {
		rule       error
		args       []string
		pos        int
		wroteUsage bool
	}{
		{rule: errArgument, args: []string{"extra"}, pos: 1},
		{rule: errArgument, args: []string{"-rate-burst=7", "extra", "more"}, pos: 2},
		{rule: errCommandLine, args: []string{"-unknown"}, pos: 1, wroteUsage: true},
		{rule: errCommandLine, args: []string{"-health-enabled"}, pos: 1, wroteUsage: true},
		{rule: errCommandLine, args: []string{"-rate-burst=3", "-conn-max-total"}, pos: 2, wroteUsage: true},
		{rule: errCommandLine, args: []string{"---rate-burst=7"}, pos: 1, wroteUsage: true},
	} {
		_, usage, err := loadWith(t, base, tc.args)
		text := fmt.Sprintf("%s: argument %d %v", commandLine, tc.pos, tc.rule)
		if !hasProblem(err, commandLine, tc.rule) || !strings.Contains(err.Error(), text) ||
			(usage != "") != tc.wroteUsage {
			t.Errorf("Load(%q) = %v, usage %d bytes, want a problem %q and usage %v", tc.args, err, len(usage),
				text, tc.wroteUsage)
		}
	}
}

// TestLoadReadsNoFlagAfterAnUnreadableArgument puts a flag outside its range after an
// unknown flag, a malformed flag and an argument that is not a flag: the problem of the
// command line is the only one.
func TestLoadReadsNoFlagAfterAnUnreadableArgument(t *testing.T) {
	base := baseEnvironment(t)
	for _, tc := range []struct {
		rule error
		args []string
	}{
		{errCommandLine, []string{"-unknown", "-rate-burst=0"}},
		{errCommandLine, []string{"---rate-burst=7", "-rate-burst=0"}},
		{errArgument, []string{"extra", "-rate-burst=0"}},
	} {
		_, _, err := loadWith(t, base, tc.args)
		checkProblems(t, fmt.Sprintf("Load(%q)", tc.args), err, wantProblem{tc.rule, commandLine})
	}
}

// TestLoadJoinsEveryProblem gives Load problems from both layers, the rules and the
// command line: each comes back joined, a configuration problem.
func TestLoadJoinsEveryProblem(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_RATE_BURST"] = "0"
	env["UWSB_SERVER_DEBUG"] = "loud"
	env[envAddress] = "0.0.0.0:8443"
	cfg, _, err := loadWith(t, env, []string{"-conn-max-total=0", "extra"})
	checkProblems(t, "five problems", err,
		wantProblem{errOutOfRange, namesOf("UWSB_RATE_BURST")}, wantProblem{errNotBool, namesOf("UWSB_SERVER_DEBUG")},
		wantProblem{errOpenRelay, namesOf(envAddress)}, wantProblem{errOutOfRange, namesOf("UWSB_CONN_MAX_TOTAL")},
		wantProblem{errArgument, commandLine})
	if cfg != nil {
		t.Errorf("Load() = %+v, want no Config beside its problems", cfg)
	}
}

// failingWriter is a usage writer whose writes fail.
type failingWriter struct{}

var errWrite = errors.New("write refused")

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

// TestLoadReturnsErrHelp requires -h, -help and --help to return ErrHelp alone with the
// usage, beside a problem of the variables.
func TestLoadReturnsErrHelp(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_RATE_BURST"] = "0"
	for _, arg := range []string{"-h", "-help", "--help"} {
		cfg, usage, err := loadWith(t, env, []string{arg})
		if cfg != nil || !errors.Is(err, ErrHelp) || errors.Is(err, ErrInvalidConfig) ||
			!strings.HasPrefix(usage, "Usage of ubyte-webssh-bridge:\n") {
			t.Errorf("Load(%s) = %v, %v, usage %q, want ErrHelp alone and the usage", arg, cfg, err, usage)
		}
	}
}

// TestLoadReturnsTheRequestSentinels requires -version to return ErrVersionRequested
// before any problem, and -health ErrHealthRequested beside a valid Config and a
// problem otherwise.
func TestLoadReturnsTheRequestSentinels(t *testing.T) {
	for _, args := range [][]string{{"-version"}, {"-version", "-rate-burst=0", "extra"}} {
		if cfg, _, err := loadWith(t, nil, args); cfg != nil || !errors.Is(err, ErrVersionRequested) {
			t.Errorf("Load(%q) = %v, %v, want ErrVersionRequested", args, cfg, err)
		}
	}
	env := baseEnvironment(t)
	cfg, _, err := loadWith(t, env, []string{"-health"})
	if !errors.Is(err, ErrHealthRequested) || cfg == nil || cfg.Server.Address != testAddress {
		t.Errorf("Load(-health) = %+v, %v, want the Config and ErrHealthRequested", cfg, err)
	}
	env["UWSB_RATE_BURST"] = "0"
	cfg, _, err = loadWith(t, env, []string{"-health"})
	if cfg != nil || errors.Is(err, ErrHealthRequested) || !hasProblem(err, namesOf("UWSB_RATE_BURST"), errOutOfRange) {
		t.Errorf("Load(-health) with a bad burst = %v, %v, want nil, its problem and no ErrHealthRequested", cfg, err)
	}
}

// TestLoadJoinsAFailedUsageWrite gives Load a usage writer that fails: its failure
// joins ErrHelp on -h and the problem of an unknown flag.
func TestLoadJoinsAFailedUsageWrite(t *testing.T) {
	cleanEnvironment(t)
	cfg, err := Load([]string{"-h"}, failingWriter{})
	if cfg != nil || !errors.Is(err, ErrHelp) || !errors.Is(err, errWrite) {
		t.Errorf("Load(-h) to a failing writer = %v, %v, want ErrHelp joined with the write's failure", cfg, err)
	}
	cfg, err = Load([]string{"-unknown"}, failingWriter{})
	if cfg != nil || !errors.Is(err, errWrite) || !hasProblem(err, commandLine, errCommandLine) {
		t.Errorf("Load(-unknown) to a failing writer = %v, %v, want nil, its problem and the write's failure",
			cfg, err)
	}
}

// TestLoadReturnsTheUnreadNames sets unread UWSB_ variables out of name order, and
// others: UnreadNames lists the unread ones with a value, in name order.
func TestLoadReturnsTheUnreadNames(t *testing.T) {
	cleanEnvironment(t)
	for name, v := range baseEnvironment(t) {
		t.Setenv(name, v)
	}
	t.Setenv("UWSB_SESSION_IDLE_TIMEOUT", "30m")
	t.Setenv("UWSB_ALPHA", "1")
	t.Setenv("UWSB_EMPTY", "")
	t.Setenv("HOST", "192.0.2.10")
	t.Setenv("XUWSB_RATE_BURST", "3")
	cfg, err := Load([]string{}, io.Discard)
	want := []string{"UWSB_ALPHA", "UWSB_SESSION_IDLE_TIMEOUT"}
	if err != nil || !slices.Equal(cfg.UnreadNames(), want) {
		t.Errorf("Load() = %v, %v, want UnreadNames %q", cfg, err, want)
	}
}

// TestLoadWritesTheGoldenUsage pins -h to testdata/ubyte-webssh-bridge-help.golden:
// each flag in name order with its help, its type unless a bool and its default unless
// zero.
func TestLoadWritesTheGoldenUsage(t *testing.T) {
	golden := fileBytes(t, filepath.Join("testdata", "ubyte-webssh-bridge-help.golden"))
	if _, usage, err := loadWith(t, nil, []string{"-h"}); !errors.Is(err, ErrHelp) || usage != string(golden) {
		t.Errorf("Load(-h) = %v, usage\n%s\nwant ErrHelp and the golden\n%s", err, usage, golden)
	}
}

// TestFlagValueStringOfTheZeroValue calls String on the zero flagValue, directly and
// through PrintDefaults: it returns "" and no flag reports a panic.
func TestFlagValueStringOfTheZeroValue(t *testing.T) {
	if got := (flagValue{}).String(); got != "" {
		t.Errorf("flagValue{}.String() = %q, want \"\"", got)
	}
	l := newLoader(&Config{})
	flags := newFlagSet(l, l.flagged(&request{}))
	var out strings.Builder
	flags.SetOutput(&out)
	flags.PrintDefaults()
	if strings.Contains(out.String(), "panic calling String") {
		t.Errorf("PrintDefaults() reports a panic of String on a zero flagValue, want none:\n%s", out.String())
	}
}

// TestLoadIsTheOnlyReaderOfTheEnvironment parses every production file of the module
// outside this package: none reads or sets the environment or declares a constant
// named default, and each clamp shape is logged as a candidate for a reader.
func TestLoadIsTheOnlyReaderOfTheEnvironment(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range scannedFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s) = %v, want nil", path, err)
		}
		for _, place := range environmentProblems(fset, f) {
			t.Errorf("%s, want the environment and the defaults in internal/config alone", place)
		}
		for _, n := range clampShapes(f) {
			t.Logf("%s: clamp candidate", fset.Position(n.Pos()))
		}
	}
}

// scannedFiles returns the Go files of the module that are not tests, outside this
// package's directory and the hidden and testdata ones.
func scannedFiles(t *testing.T) []string {
	t.Helper()
	own, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("filepath.Abs(.) = %v, want nil", err)
	}
	var files []string
	err = filepath.WalkDir(filepath.Join(own, moduleRoot), func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && skipsDir(path, own):
			return filepath.SkipDir
		case !d.IsDir() && filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go"):
			files = append(files, path)
		}
		return nil
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("walking the module = %v, %d files, want nil and every production file", err, len(files))
	}
	return files
}

// skipsDir reports whether the scan skips the directory at path: own, the package's,
// a hidden one, a testdata one or node_modules.
func skipsDir(path, own string) bool {
	name := filepath.Base(path)
	return path == own || name == "testdata" || name == "node_modules" || strings.HasPrefix(name, ".")
}

// TestLoadScansFindEachShape runs the scans of TestLoadIsTheOnlyReaderOfTheEnvironment
// over sources that hold each shape they find, os under any name, and none.
func TestLoadScansFindEachShape(t *testing.T) {
	for _, tc := range []struct {
		src                 string
		environment, clamps int
	}{
		{`import "os"; func f() { _ = os.Getenv("A"); _, _ = os.LookupEnv("B"); _ = os.Args }`, 2, 0},
		{`import sys "os"; func f() { _ = sys.Environ(); _ = sys.ExpandEnv("$C"); _ = sys.Setenv("A", "") }`, 3, 0},
		{`import "strings"; func f() { _ = strings.TrimSpace("Getenv") }`, 0, 0},
		{`const defaultSize = 4; const DefaultName, other = "a", "b"`, 2, 0},
		{`const sizeDefault = 4; var defaultSize = 4; func f() { const defaultX = 1 }`, 0, 0},
		{`func f(n, m int) { if n <= 0 { n = 4 }; if n == 0 { n = m }; if n < 1 { n = 1 }; _ = max(n, 1) }`, 0, 4},
		{`func f(n, m int) { if n <= 0 { m = 4 }; if n <= 0 { n = 4; m = 1 }; if n < 0 { n = 0 } }`, 0, 0},
		{`func f(n, m int) { if n == 1 { n = 2 }; if m > 0 { n = 2 }; _ = max(n, 2); _ = min(n, 1) }`, 0, 0},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "p.go", "package p; "+tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parser.ParseFile(%q) = %v, want nil", tc.src, err)
		}
		got, want := [2]int{len(environmentProblems(fset, f)), len(clampShapes(f))}, [2]int{tc.environment, tc.clamps}
		if got != want {
			t.Errorf("scans of %q found %v (environment, clamps), want %v", tc.src, got, want)
		}
	}
}

// environmentProblems returns the places of f, a file of fset, that read or set the
// environment, or declare a package-level constant named default.
func environmentProblems(fset *token.FileSet, f *ast.File) []string {
	osName := importName(f, "os")
	var problems []string
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok &&
			selects(call.Fun, osName, "Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv") {
			problems = append(problems, fset.Position(call.Pos()).String()+": the environment")
		}
		return true
	})
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if strings.HasPrefix(strings.ToLower(name.Name), "default") {
					problems = append(problems, fset.Position(name.Pos()).String()+": a default")
				}
			}
		}
	}
	return problems
}

// importName returns the name file f gives the package of path, or "" when f does not
// import it.
func importName(f *ast.File, path string) string {
	for _, spec := range f.Imports {
		if strings.Trim(spec.Path.Value, `"`) != path {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return path
	}
	return ""
}

// selects reports whether expr is pkg.name for one of names, pkg not empty.
func selects(expr ast.Expr, pkg string, names ...string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || pkg == "" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && slices.Contains(names, sel.Sel.Name)
}

// clampShapes returns the clamps of f: an if on x <= 0, x == 0 or x < 1 whose body is
// one assignment to x, and max(x, 1).
func clampShapes(f *ast.File) []ast.Node {
	var out []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt:
			if clampsByIf(n) {
				out = append(out, n)
			}
		case *ast.CallExpr:
			if types.ExprString(n.Fun) == "max" && slices.ContainsFunc(n.Args, isOne) {
				out = append(out, n)
			}
		}
		return true
	})
	return out
}

// clampsByIf reports whether s tests x <= 0, x == 0 or x < 1 and only assigns x.
func clampsByIf(s *ast.IfStmt) bool {
	cond, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || !testsBelowOne(cond) || len(s.Body.List) != 1 {
		return false
	}
	assign, ok := s.Body.List[0].(*ast.AssignStmt)
	return ok && assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 &&
		types.ExprString(assign.Lhs[0]) == types.ExprString(cond.X)
}

// testsBelowOne reports whether cond is x <= 0, x == 0 or x < 1.
func testsBelowOne(cond *ast.BinaryExpr) bool {
	lit, ok := cond.Y.(*ast.BasicLit)
	return ok && (lit.Value == "0" && (cond.Op == token.LEQ || cond.Op == token.EQL) ||
		lit.Value == "1" && cond.Op == token.LSS)
}

func isOne(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Value == "1"
}

// TestLoadReadsTheTarget sets the target through its variable and its flag: each
// loads in its canonical spelling, the flag over the variable.
func TestLoadReadsTheTarget(t *testing.T) {
	env := baseEnvironment(t)
	env[envTarget] = "Device.Example.TEST.:22"
	cfg, _, err := loadWith(t, env, []string{})
	want := documentedDefaults(env)
	want.SSH.Target = "device.example.test:22"
	checkConfig(t, "the variable", cfg, err, &want)
	cfg, _, err = loadWith(t, env, []string{"-ssh-target=[2001:0db8:0::1]:22"})
	want.SSH.Target = "[2001:db8::1]:22"
	checkConfig(t, "the flag over the variable", cfg, err, &want)
}
