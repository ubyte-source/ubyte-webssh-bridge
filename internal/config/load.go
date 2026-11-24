package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// commandName names the command in the usage, and commandLine its arguments in a
// problem.
const (
	commandName = "ubyte-webssh-bridge"
	commandLine = "command line"
)

// envPrefix starts every variable the table reads.
const envPrefix = "UWSB_"

// request lists what the command line asks for besides the settings.
type request struct {
	version bool
	health  bool
}

// joinedError is an error that joins several, as errors.Join returns.
type joinedError interface {
	error
	// Unwrap returns the errors it joins.
	Unwrap() []error
}

// loader reads one configuration through the table of its settings.
type loader struct {
	table    []setting
	problems []error
}

// flagValue reads the flag of s into its setting through the loader, so every flag
// parses its value: a malformed one is a problem, not the end of the line.
type flagValue struct {
	l *loader
	s *setting
}

// Load returns the Config of the defaults, the UWSB_ variables and the flags of args,
// with ErrHealthRequested for -health; else nil with ErrHelp, ErrVersionRequested or
// the joined problems, writing the usage to usage on -h and on a flag that fails.
func Load(args []string, usage io.Writer) (*Config, error) {
	c := &Config{}
	l := newLoader(c)
	var req request
	defined := l.flagged(&req)
	fs := newFlagSet(l, defined)
	l.readEnvironment()
	if err := l.readFlags(fs, defined, args, usage); err != nil {
		return nil, err
	}
	if req.version {
		return nil, ErrVersionRequested
	}
	l.validate(c)
	l.loadCertificate(&c.Server)
	if err := errors.Join(l.problems...); err != nil {
		return nil, err
	}
	c.unread = l.unread()
	if req.health {
		return c, ErrHealthRequested
	}
	return c, nil
}

// newLoader returns the loader of the settings of c, each holding its default.
func newLoader(c *Config) *loader {
	l := &loader{table: settings(c)}
	for i := range l.table {
		l.table[i].value.reset()
	}
	return l
}

// set reads raw, the value of s that its variable or its flag gives: each fault is a
// problem of s, and the field keeps the value of the layer below.
func (l *loader) set(s *setting, raw string) {
	s.given = true
	err := s.value.read(raw)
	if err == nil {
		return
	}
	s.failed = true
	faults := []error{err}
	if joined, ok := errors.AsType[joinedError](err); ok {
		faults = joined.Unwrap()
	}
	for _, fault := range faults {
		l.fail(s, fault)
	}
}

// fail records that s breaks rule.
func (l *loader) fail(s *setting, rule error) {
	l.problems = append(l.problems, newProblem(s.names(), rule))
}

// setting returns the setting of the table that writes field.
func (l *loader) setting(field any) *setting {
	return &l.table[slices.IndexFunc(l.table, func(s setting) bool { return s.value.field() == field })]
}

// readEnvironment sets every setting whose variable has a value; an empty variable
// is unset.
func (l *loader) readEnvironment() {
	for i := range l.table {
		if raw := os.Getenv(l.table[i].env); raw != "" {
			l.set(&l.table[i], raw)
		}
	}
}

// unread returns, in name order, the UWSB_ variables with a value that no setting
// reads.
func (l *loader) unread() []string {
	var names []string
	for _, pair := range os.Environ() {
		name, raw, _ := strings.Cut(pair, "=")
		if raw == "" || !strings.HasPrefix(name, envPrefix) {
			continue
		}
		if !slices.ContainsFunc(l.table, func(s setting) bool { return s.env == name }) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// flagged returns the settings of the table, each with its flag, after -health and
// -version, which write into req.
func (l *loader) flagged(req *request) []*setting {
	requests := []*setting{
		{flag: "health", usage: "dial the listen address and exit 0 when it accepts a TCP connection",
			value: boolOf(&req.health)},
		{flag: "version", usage: "print the version and the Go release and exit", value: boolOf(&req.version)},
	}
	defined := make([]*setting, 0, len(requests)+len(l.table))
	defined = append(defined, requests...)
	for i := range l.table {
		defined = append(defined, &l.table[i])
	}
	return defined
}

// readFlags parses args with fs, the flags of defined, an empty value unset. It writes
// the usage on -h, returning ErrHelp with any write failure, and on an unknown,
// valueless or malformed flag, which no problem quotes.
func (l *loader) readFlags(fs *flag.FlagSet, defined []*setting, args []string, usage io.Writer) error {
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return errors.Join(ErrHelp, writeUsage(usage, fs, defined))
	case err != nil:
		l.problems = append(l.problems,
			newProblem(commandLine, fmt.Errorf("argument %d %w", failedArgument(args, fs, defined), errCommandLine)),
			writeUsage(usage, fs, defined))
	case fs.NArg() > 0:
		l.problems = append(l.problems,
			newProblem(commandLine, fmt.Errorf("argument %d %w", len(args)-fs.NArg()+1, errArgument)))
	}
	return nil
}

// Set reads raw into the setting, an empty raw leaving it unset; without a loader
// nothing reads.
func (v flagValue) Set(raw string) error {
	if v.l != nil && raw != "" {
		v.l.set(v.s, raw)
	}
	return nil
}

// String returns the text of the setting's value, empty for the zero flagValue.
func (v flagValue) String() string {
	if v.s == nil {
		return ""
	}
	return v.s.value.String()
}

// IsBoolFlag reports whether the flag stands alone for true.
func (v flagValue) IsBoolFlag() bool { return v.s.value.kind() == kindBool }

// newFlagSet defines the flag of each setting of defined, read through l, with the
// value the setting holds as its default; with a nil l the flags read nothing.
func newFlagSet(l *loader, defined []*setting) *flag.FlagSet {
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	for _, s := range defined {
		fs.Var(flagValue{l: l, s: s}, s.flag, s.usage)
	}
	return fs
}

// failedArgument returns the position, from 1, of the argument fs failed to read in
// args: the last one it took when those fail again alone, else the next one.
func failedArgument(args []string, fs *flag.FlagSet, defined []*setting) int {
	taken := args[:len(args)-fs.NArg()]
	if newFlagSet(nil, defined).Parse(taken) != nil {
		return len(taken)
	}
	return len(taken) + 1
}

// writeUsage writes the usage of fs, the flags of defined, to w as flag.PrintDefaults
// lays it out, with the type each value reads; it fails wrapping the write's failure.
func writeUsage(w io.Writer, fs *flag.FlagSet, defined []*setting) error {
	kinds := make(map[string]string, len(defined))
	for _, s := range defined {
		kinds[s.flag] = s.value.kind()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Usage of %s:\n", commandName)
	fs.VisitAll(func(f *flag.Flag) {
		kind := kinds[f.Name]
		fmt.Fprintf(&b, "  -%s", f.Name)
		if kind != kindBool {
			fmt.Fprintf(&b, " %s", kind)
		}
		def := ""
		switch {
		case f.DefValue == zeroText(kind):
		case kind == kindString || kind == kindList:
			def = fmt.Sprintf(" (default %q)", f.DefValue)
		default:
			def = " (default " + f.DefValue + ")"
		}
		fmt.Fprintf(&b, "\n    \t%s%s\n", f.Usage, def)
	})
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write the usage: %w", err)
	}
	return nil
}

// zeroText returns the text of the zero value of kind, which the usage omits.
func zeroText(kind string) string {
	switch kind {
	case kindBool:
		return "false"
	case kindDuration:
		return "0s"
	case kindInt:
		return "0"
	default:
		return ""
	}
}
