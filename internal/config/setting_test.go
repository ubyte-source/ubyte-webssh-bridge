package config

import (
	"errors"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSettingsMatchTheVariablesGolden pins the variables and their flags, in table
// order, as testdata/variables.golden lists them, each name once and in name order.
func TestSettingsMatchTheVariablesGolden(t *testing.T) {
	golden := fileBytes(t, filepath.Join("testdata", "variables.golden"))
	table := newTable()
	lines := make([]string, 0, len(table))
	for _, s := range table {
		lines = append(lines, s.env+" -"+s.flag)
		if want := flagOf(s.env); "-"+s.flag != want {
			t.Errorf("flag of %s = -%s, want %s", s.env, s.flag, want)
		}
	}
	if got := strings.Join(lines, "\n") + "\n"; got != string(golden) {
		t.Fatalf("table =\n%s\nwant testdata/variables.golden\n%s", got, golden)
	}
	if !slices.IsSortedFunc(table, func(a, b setting) int { return strings.Compare(a.env, b.env) }) {
		t.Error("table variables are not in name order, want them sorted")
	}
}

// TestSettingsKeepTheirRangesAtTheirDefaults reads the text of each default back: it
// keeps the setting's range or grammar and gives the same text.
func TestSettingsKeepTheirRangesAtTheirDefaults(t *testing.T) {
	for _, s := range newTable() {
		s.value.reset()
		text := s.value.String()
		if text == "" {
			continue
		}
		if err := s.value.read(text); err != nil || s.value.String() != text {
			t.Errorf("default of %s = %q: read = %v, %q, want nil and the same text", s.env, text, err,
				s.value.String())
		}
	}
}

// rangeRow is a row of testdata/ranges.tsv: a setting's bounds, the values one past
// them, and the partners its cross rules need at the least bound and at the greatest.
type rangeRow struct {
	withMin, withMax       map[string]string
	env                    string
	min, max, below, above string
}

// rangeColumns is the count of the columns of testdata/ranges.tsv.
const rangeColumns = 7

func readRanges(t *testing.T) []rangeRow {
	t.Helper()
	data := string(fileBytes(t, filepath.Join("testdata", "ranges.tsv")))
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	rows := make([]rangeRow, 0, len(lines)-1)
	for _, line := range lines[1:] {
		f := strings.Split(line, "\t")
		if len(f) != rangeColumns {
			t.Fatalf("ranges row %q has %d columns, want %d", line, len(f), rangeColumns)
		}
		rows = append(rows, rangeRow{env: f[0], min: f[1], max: f[2], below: f[3], above: f[4],
			withMin: partners(f[5]), withMax: partners(f[6])})
	}
	return rows
}

// partners returns the settings a with column of testdata/ranges.tsv names, each as
// NAME=value, and none for "-".
func partners(column string) map[string]string {
	out := map[string]string{}
	for pair := range strings.FieldsSeq(strings.TrimPrefix(column, "-")) {
		name, v, _ := strings.Cut(pair, "=")
		out[name] = v
	}
	return out
}

// TestSettingsAcceptEachBoundAndRefuseOnePast requires a ranges row per numeric
// setting and loads each with its partners: both bounds load, and each value one past
// stops the boot with a range problem naming it.
func TestSettingsAcceptEachBoundAndRefuseOnePast(t *testing.T) {
	rows := readRanges(t)
	for _, s := range newTable() {
		numeric := s.value.kind() == kindInt || s.value.kind() == kindDuration
		if numeric != slices.ContainsFunc(rows, func(r rangeRow) bool { return r.env == s.env }) {
			t.Errorf("%s numeric %v, want a row in testdata/ranges.tsv exactly for a numeric setting", s.env, numeric)
		}
	}
	base := baseEnvironment(t)
	for _, row := range rows {
		for _, edge := range []struct {
			with        map[string]string
			bound, past string
		}{{row.withMin, row.min, row.below}, {row.withMax, row.max, row.above}} {
			env := maps.Clone(base)
			maps.Copy(env, edge.with)
			env[row.env] = edge.bound
			if _, _, err := loadWith(t, env, []string{}); err != nil {
				t.Errorf("%s=%s with %v: Load() error = %v, want nil", row.env, edge.bound, edge.with, err)
			}
			env[row.env] = edge.past
			if _, _, err := loadWith(t, env, []string{}); !hasProblem(err, namesOf(row.env), errOutOfRange) {
				t.Errorf("%s=%s: Load() error = %v, want a problem of it wrapping %v", row.env, edge.past, err,
					errOutOfRange)
			}
		}
	}
}

// readmeText returns the README of the module.
func readmeText(t *testing.T) string {
	t.Helper()
	return string(fileBytes(t, filepath.Join(moduleRoot, "README.md")))
}

// readmeColumns is the count of the columns of README's Configuration table.
const readmeColumns = 6

// readmeRow is a row of README's Configuration table: its Flag, Variable and Default
// cells without their code spans, and its Type and Range cells.
type readmeRow struct {
	flag, env, kind, defaultCell, bounds string
}

// readmeRows returns the rows of README's Configuration table in README order.
func readmeRows(t *testing.T) []readmeRow {
	t.Helper()
	var rows []readmeRow
	inTable := false
	for line := range strings.Lines(readmeText(t)) {
		switch {
		case !strings.HasPrefix(line, "|"):
			inTable = false
		case strings.HasPrefix(line, "| Flag | Variable | Type | Default | Range | Meaning |"):
			inTable = true
		case inTable && !strings.HasPrefix(line, "|--"):
			cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
			if len(cells) != readmeColumns {
				t.Fatalf("README row %q has %d cells, want %d", line, len(cells), readmeColumns)
			}
			rows = append(rows, readmeRow{flag: codeText(cells[0]), env: codeText(cells[1]),
				kind: strings.TrimSpace(cells[2]), defaultCell: codeText(cells[3]),
				bounds: strings.TrimSpace(cells[4])})
		}
	}
	return rows
}

// codeText returns the text of cell, a table cell, without its code span.
func codeText(cell string) string {
	return strings.Trim(strings.TrimSpace(cell), "`")
}

// typeWord returns the word of README's Type column for a value of kind.
func typeWord(kind string) string {
	if kind == kindBool {
		return "bool"
	}
	return kind
}

// TestSettingsMatchTheReadmeTable pins README's Configuration table to the table and
// the requests: each flag with its variable and type, each default as its value reads
// it, and each numeric range opening as testdata/ranges.tsv states it.
func TestSettingsMatchTheReadmeTable(t *testing.T) {
	bounds := map[string]string{}
	for _, r := range readRanges(t) {
		bounds[r.env] = r.min + "-" + r.max
	}
	l := newLoader(&Config{})
	defined := l.flagged(&request{})
	rows := readmeRows(t)
	if len(rows) != len(defined) {
		t.Fatalf("README lists %d flags, want the %d of the command line", len(rows), len(defined))
	}
	for _, row := range rows {
		i := slices.IndexFunc(defined, func(s *setting) bool { return "-"+s.flag == row.flag })
		if i < 0 {
			t.Errorf("README lists %s, which the command line does not define", row.flag)
			continue
		}
		s := defined[i]
		env := envCell(s.env)
		if row.env != env || row.kind != typeWord(s.value.kind()) || !strings.HasPrefix(row.bounds, bounds[s.env]) {
			t.Errorf("README row of %s = %s %s %q, want %s %s and a range opening %q", row.flag, row.env, row.kind,
				row.bounds, env, typeWord(s.value.kind()), bounds[s.env])
		}
		checkReadmeDefault(t, s, row.defaultCell)
	}
}

// envCell returns README's Variable cell of a flag whose variable is env: the variable,
// or none for a request.
func envCell(env string) string {
	if env == "" {
		return "none"
	}
	return env
}

// checkReadmeDefault fails t unless def, the README Default cell of s, reads as its
// default: empty for a request, "empty" for an empty default.
func checkReadmeDefault(t *testing.T, s *setting, def string) {
	t.Helper()
	documented := newTable()
	i := slices.IndexFunc(documented, func(d setting) bool { return d.env == s.env })
	switch {
	case i < 0:
		if def != "" {
			t.Errorf("README default of -%s = %q, want none", s.flag, def)
		}
	case def == "empty":
		if s.value.String() != "" {
			t.Errorf("README default of %s is empty, want %q", s.env, s.value.String())
		}
	case documented[i].value.read(def) != nil || documented[i].value.String() != s.value.String():
		t.Errorf("README default of %s = %q, which reads %q, want %q", s.env, def, documented[i].value.String(),
			s.value.String())
	}
}

// TestSettingsMatchTheEnvExample reads every "# UWSB_NAME=value" line of
// .env.example: the names are the table's, once each, and each value reads as the
// default.
func TestSettingsMatchTheEnvExample(t *testing.T) {
	defaults := newLoader(&Config{}).table
	documented := newTable()
	var names []string
	for line := range strings.Lines(string(fileBytes(t, filepath.Join(moduleRoot, ".env.example")))) {
		pair, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "# "+envPrefix)
		if !ok {
			continue
		}
		name, text, _ := strings.Cut(envPrefix+pair, "=")
		names = append(names, name)
		i := slices.IndexFunc(documented, func(s setting) bool { return s.env == name })
		if i < 0 {
			t.Errorf(".env.example sets %s, which the table does not hold", name)
			continue
		}
		if text != "" && documented[i].value.read(text) != nil {
			t.Errorf(".env.example sets %s=%s, which does not read", name, text)
		}
		if got, want := documented[i].value.String(), defaults[i].value.String(); got != want {
			t.Errorf(".env.example sets %s=%s, which reads %q, want the default %q", name, text, got, want)
		}
	}
	slices.Sort(names)
	want := make([]string, 0, len(defaults))
	for _, s := range defaults {
		want = append(want, s.env)
	}
	if !slices.Equal(names, want) {
		t.Errorf(".env.example sets %q, want %q", names, want)
	}
}

// TestTypedStringOfTheZeroValue calls String on the zero typed: it returns "".
func TestTypedStringOfTheZeroValue(t *testing.T) {
	if got := (typed[int]{}).String(); got != "" {
		t.Errorf("typed[int]{}.String() = %q, want \"\"", got)
	}
}

// TestParsePrefixesReadsTheEntries reads entries at each edge of the grammar: an
// address is a /32 or a /128, a prefix is masked, and an IPv4-mapped one is unmapped.
func TestParsePrefixesReadsTheEntries(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"192.0.2.7", "192.0.2.7/32"},
		{"2001:db8::7", "2001:db8::7/128"},
		{"192.0.2.7/24", "192.0.2.0/24"},
		{"::ffff:192.0.2.1", "192.0.2.1/32"},
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"},
		{"::ffff:0.0.0.0/96", "0.0.0.0/0"},
		{" 192.0.2.1 ,  2001:db8::/32 ", "192.0.2.1/32,2001:db8::/32"},
		{"127.0.0.0/8,::1/128", "127.0.0.0/8,::1/128"},
		{"2001:db8::1/64,198.51.100.255/25", "2001:db8::/64,198.51.100.128/25"},
	} {
		got, err := parsePrefixes(tc.raw)
		if err != nil || formatPrefixes(got) != tc.want {
			t.Errorf("parsePrefixes(%q) = %q, %v, want %q", tc.raw, formatPrefixes(got), err, tc.want)
		}
	}
}

// TestParsePrefixesRefusesEachBadEntry refuses entries that are no address or prefix,
// carry a zone, are empty or map a prefix shorter than /96: one fault per entry,
// quoting the entry alone.
func TestParsePrefixesRefusesEachBadEntry(t *testing.T) {
	for _, entry := range []string{
		"::ffff:0.0.0.0/95", "fe80::1%eth0", "", "192.0.2.300", "host.example.test", "192.0.2.0/33",
		"fe80::1%eth0/64",
	} {
		raw := "198.51.100.1," + entry + ",203.0.113.0/24"
		_, err := parsePrefixes(raw)
		want := `"` + entry + `" is not an IP address or a CIDR prefix without a zone`
		if !errors.Is(err, errTrustedProxy) || err.Error() != want {
			t.Errorf("parsePrefixes(%q) error = %v, want %q", raw, err, want)
		}
	}
	env := baseEnvironment(t)
	env["UWSB_SERVER_TRUSTED_PROXIES"] = "bad, 192.0.2.1, ,unknown"
	_, _, err := loadWith(t, env, []string{})
	names := namesOf("UWSB_SERVER_TRUSTED_PROXIES")
	checkProblems(t, "three bad entries", err, wantProblem{errTrustedProxy, names},
		wantProblem{errTrustedProxy, names}, wantProblem{errTrustedProxy, names})
}

// TestParsePrefixesBoundsTheEntries reads 1 and 64 entries and refuses 65, naming the
// count and no entry.
func TestParsePrefixesBoundsTheEntries(t *testing.T) {
	entries := make([]string, 0, maxTrustedProxies+1)
	for i := range maxTrustedProxies + 1 {
		entries = append(entries, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
	}
	for _, n := range []int{1, 64} {
		got, err := parsePrefixes(strings.Join(entries[:n], ","))
		if err != nil || len(got) != n {
			t.Errorf("parsePrefixes of %d entries = %d prefixes, %v, want %d and nil", n, len(got), err, n)
		}
	}
	env := baseEnvironment(t)
	env["UWSB_SERVER_TRUSTED_PROXIES"] = strings.Join(entries, ",")
	_, _, err := loadWith(t, env, []string{})
	names := namesOf("UWSB_SERVER_TRUSTED_PROXIES")
	checkProblems(t, "65 entries", err, wantProblem{errTooManyProxies, names})
	if want := names + ": 65 entries are more than 64"; err == nil || err.Error() != want {
		t.Errorf("65 entries: Load() error = %v, want %q", err, want)
	}
}

// TestWithinWritesTheRange checks a value of each kind outside its range: the text
// names the value and both bounds as the kind writes them.
func TestWithinWritesTheRange(t *testing.T) {
	c := &Config{}
	l := newLoader(c)
	for field, tc := range map[any]struct{ raw, want string }{
		&c.Rate.Burst:       {"0", "0 is outside 1-10000"},
		&c.Rate.Interval:    {"2h", "2h0m0s is outside 100ms-1h0m0s"},
		&c.SSH.LoginTimeout: {"500ms", "500ms is outside 1s-1h0m0s"},
	} {
		err := l.setting(field).value.read(tc.raw)
		if err == nil || !errors.Is(err, errOutOfRange) || err.Error() != tc.want {
			t.Errorf("read(%s) = %v, want %q", tc.raw, err, tc.want)
		}
	}
}
