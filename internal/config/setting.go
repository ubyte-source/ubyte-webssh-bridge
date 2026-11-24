package config

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The defaults of the settings, each named for its setting.
const (
	defaultConnMaxPerHost        = 10
	defaultConnMaxTotal          = 1000
	defaultRateBurst             = 10
	defaultRateInterval          = 2 * time.Second
	defaultServerAddress         = ":8443"
	defaultServerCert            = "/data/certificate.crt"
	defaultServerKey             = "/data/certificate.key"
	defaultServerShutdownTimeout = 30 * time.Second
	defaultServerTrustedProxies  = "127.0.0.0/8,::1/128"
	defaultSSHConnectTimeout     = 10 * time.Second
	defaultSSHLoginTimeout       = 120 * time.Second
	defaultWSHandshakeTimeout    = 10 * time.Second
)

// The bounds of the ranges: a wait of a peer from minWait to maxConnect, a login and
// a stop from minLogin to maxWait, and the counts up to maxSessions and maxBurst.
const (
	minWait     = 100 * time.Millisecond
	minLogin    = time.Second
	maxConnect  = 5 * time.Minute
	maxWait     = time.Hour
	maxSessions = 100000
	maxBurst    = 10000
)

// maxTrustedProxies bounds the entries of -server-trusted-proxies, and mappedBits is
// the length of the IPv4-mapped prefix ::ffff:0:0/96.
const (
	maxTrustedProxies = 64
	mappedBits        = 96
)

// The type names of the usage; a bool has none.
const (
	kindString   = "string"
	kindInt      = "int"
	kindDuration = "duration"
	kindList     = "list"
	kindBool     = ""
)

// listSeparator separates the entries of a list, and faultFormat writes a text that
// does not read before its rule.
const (
	listSeparator = ","
	faultFormat   = "%q %w"
)

// value is the field of a setting: read parses a text into it, String writes it back.
type value interface {
	// read writes the value raw gives when it parses and keeps its range, and returns
	// nil; otherwise it keeps the field and returns the fault, or the faults joined.
	read(raw string) error
	// String returns the text of the field.
	String() string
	// field returns the pointer to the field read writes.
	field() any
	// kind names the type of the value in the usage.
	kind() string
	// reset writes the default.
	reset()
}

// typed is the value of a setting of type T: its default, the parser of its text, its
// range, the writer of its value and the word of its type in the usage.
type typed[T any] struct {
	p          *T
	def        T
	parse      func(string) (T, error)
	constraint func(T) error
	format     func(T) string
	word       string
}

func (v typed[T]) read(raw string) error {
	x, err := v.parse(raw)
	if err != nil {
		return err
	}
	err = v.constraint(x)
	if err != nil {
		return err
	}
	*v.p = x
	return nil
}

// String returns the text of the field, empty for the zero typed.
func (v typed[T]) String() string {
	if v.p == nil {
		return ""
	}
	return v.format(*v.p)
}

func (v typed[T]) field() any   { return v.p }
func (v typed[T]) kind() string { return v.word }
func (v typed[T]) reset()       { *v.p = v.def }

// setting is one entry of the table of names: a variable and its flag, the help of the
// flag and the value both read.
type setting struct {
	value value
	env   string
	flag  string
	usage string
	// given records that a layer gave the setting a value, one that does not read too.
	given bool
	// failed records that a layer gave the setting a value that does not read.
	failed bool
}

// names returns the flag of s and, when it has one, its variable in parentheses.
func (s *setting) names() string {
	if s.env == "" {
		return "-" + s.flag
	}
	return "-" + s.flag + " (" + s.env + ")"
}

// settings returns the settings of c in name order: each variable, its flag, its help
// and its value with its default, its parser and its range or grammar.
func settings(c *Config) []setting {
	return slices.Concat(connSettings(&c.Conn), rateSettings(&c.Rate), serverSettings(&c.Server),
		sshSettings(&c.SSH), wsSettings(&c.WS))
}

func connSettings(c *ConnConfig) []setting {
	return []setting{
		{env: "UWSB_CONN_MAX_PER_HOST", flag: "conn-max-per-host",
			usage: "concurrent sessions to one target on the path route, at most -conn-max-total",
			value: intIn(&c.MaxPerHost, defaultConnMaxPerHost, 1, maxSessions)},
		{env: "UWSB_CONN_MAX_TOTAL", flag: "conn-max-total", usage: "concurrent sessions of the process",
			value: intIn(&c.MaxTotal, defaultConnMaxTotal, 1, maxSessions)},
	}
}

func rateSettings(r *RateConfig) []setting {
	return []setting{
		{env: "UWSB_RATE_BURST", flag: "rate-burst", usage: "new sessions one client address opens at once",
			value: intIn(&r.Burst, defaultRateBurst, 1, maxBurst)},
		{env: "UWSB_RATE_INTERVAL", flag: "rate-interval",
			usage: "time a client address takes to regain -rate-burst new sessions",
			value: durationIn(&r.Interval, defaultRateInterval, minWait, maxWait)},
	}
}

func serverSettings(s *ServerConfig) []setting {
	return []setting{
		{env: "UWSB_SERVER_ADDRESS", flag: "server-address",
			usage: "TLS listen address, host:port; beyond loopback it needs -ssh-target",
			value: typed[string]{p: &s.Address, def: defaultServerAddress, parse: listenAddress,
				constraint: anyValue[string], format: formatText, word: kindString}},
		{env: "UWSB_SERVER_CERT", flag: "server-cert", usage: "PEM file of the TLS certificate and its chain",
			value: textOf(&s.CertFile, defaultServerCert)},
		{env: "UWSB_SERVER_DEBUG", flag: "server-debug", usage: "write the debug records too",
			value: boolOf(&s.Debug)},
		{env: "UWSB_SERVER_KEY", flag: "server-key", usage: "PEM file of the TLS private key",
			value: textOf(&s.KeyFile, defaultServerKey)},
		{env: "UWSB_SERVER_SHUTDOWN_TIMEOUT", flag: "server-shutdown-timeout",
			usage: "time the sessions have to end after SIGINT or SIGTERM",
			value: durationIn(&s.ShutdownTimeout, defaultServerShutdownTimeout, minLogin, maxWait)},
		{env: "UWSB_SERVER_TRUSTED_PROXIES", flag: "server-trusted-proxies",
			usage: "IPs and CIDR prefixes of proxies whose X-Forwarded-For and X-Real-IP name the client",
			value: prefixesOf(&s.TrustedProxies)},
	}
}

func sshSettings(s *SSHConfig) []setting {
	return []setting{
		{env: "UWSB_SSH_CONNECT_TIMEOUT", flag: "ssh-connect-timeout",
			usage: "time to open the TCP connection to the target",
			value: durationIn(&s.ConnectTimeout, defaultSSHConnectTimeout, minWait, maxConnect)},
		{env: "UWSB_SSH_LOGIN_TIMEOUT", flag: "ssh-login-timeout",
			usage: "time from the TCP connection to the started shell, the user's answers included",
			value: durationIn(&s.LoginTimeout, defaultSSHLoginTimeout, minLogin, maxWait)},
		{env: "UWSB_SSH_TARGET", flag: "ssh-target",
			usage: "host:port every session reaches through /ws; empty: /ws/{host}/{port}, on a loopback listener only",
			value: typed[string]{p: &s.Target, parse: parseTarget, constraint: anyValue[string], format: formatText,
				word: kindString}},
	}
}

func wsSettings(w *WSConfig) []setting {
	return []setting{
		{env: "UWSB_WS_HANDSHAKE_TIMEOUT", flag: "ws-handshake-timeout",
			usage: "time a client has to send its request headers and its connect message",
			value: durationIn(&w.HandshakeTimeout, defaultWSHandshakeTimeout, minWait, maxConnect)},
	}
}

func textOf(p *string, def string) value {
	return typed[string]{p: p, def: def, parse: parseText, constraint: anyValue[string], format: formatText,
		word: kindString}
}

func intIn(p *int, def, lo, hi int) value {
	return typed[int]{p: p, def: def, parse: parseInt, constraint: within(lo, hi, strconv.Itoa),
		format: strconv.Itoa, word: kindInt}
}

func durationIn(p *time.Duration, def, lo, hi time.Duration) value {
	return typed[time.Duration]{p: p, def: def, parse: parseDuration,
		constraint: within(lo, hi, time.Duration.String), format: time.Duration.String, word: kindDuration}
}

// boolOf is the value of a flag that stands alone for true, false by default.
func boolOf(p *bool) value {
	return typed[bool]{p: p, parse: parseBool, constraint: anyValue[bool], format: strconv.FormatBool,
		word: kindBool}
}

// prefixesOf is the value of the trusted proxies, the loopback prefixes by default.
func prefixesOf(p *[]netip.Prefix) value {
	return typed[[]netip.Prefix]{p: p, def: defaultPrefixes(), parse: parsePrefixes,
		constraint: anyValue[[]netip.Prefix], format: formatPrefixes, word: kindList}
}

// defaultPrefixes returns the prefixes of defaultServerTrustedProxies.
func defaultPrefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	for entry := range strings.SplitSeq(defaultServerTrustedProxies, listSeparator) {
		prefixes = append(prefixes, netip.MustParsePrefix(entry))
	}
	return prefixes
}

func parseText(s string) (string, error) { return s, nil }

func formatText(s string) string { return s }

func parseInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf(faultFormat, s, errNotInteger)
	}
	return n, nil
}

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf(faultFormat, s, errNotDuration)
	}
	return d, nil
}

func parseBool(s string) (bool, error) {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf(faultFormat, s, errNotBool)
	}
	return b, nil
}

// parsePrefixes reads at most maxTrustedProxies entries separated by commas, each an
// address or a prefix; each entry it cannot read is a fault of its own.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	entries := strings.Split(s, listSeparator)
	if len(entries) > maxTrustedProxies {
		return nil, fmt.Errorf("%d %w %d", len(entries), errTooManyProxies, maxTrustedProxies)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	var faults []error
	for _, entry := range entries {
		entry = strings.Trim(entry, " ")
		prefix, ok := proxyPrefix(entry)
		if !ok {
			faults = append(faults, fmt.Errorf(faultFormat, entry, errTrustedProxy))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, errors.Join(faults...)
}

// proxyPrefix returns the prefix of entry, masked and unmapped: an address is a /32
// or a /128, and an IPv4-mapped prefix of at least 96 bits the IPv4 prefix it maps.
func proxyPrefix(entry string) (netip.Prefix, bool) {
	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		read := err == nil && addr.Zone() == ""
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), read
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, false
	}
	if addr := prefix.Addr(); addr.Is4In6() {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-mappedBits).Masked(), prefix.Bits() >= mappedBits
	}
	return prefix.Masked(), true
}

func formatPrefixes(prefixes []netip.Prefix) string {
	texts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		texts = append(texts, p.String())
	}
	return strings.Join(texts, listSeparator)
}

// within returns the rule of the range from lo to hi, which writes values with format.
func within[T cmp.Ordered](lo, hi T, format func(T) string) func(T) error {
	return func(v T) error {
		if v >= lo && v <= hi {
			return nil
		}
		return fmt.Errorf("%s %w %s-%s", format(v), errOutOfRange, format(lo), format(hi))
	}
}

// anyValue is the rule of a value whose parser alone decides.
func anyValue[T any](T) error { return nil }
