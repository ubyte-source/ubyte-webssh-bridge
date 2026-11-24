package config

import (
	"errors"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestJoinTargetGivesOneSpelling joins hosts and ports at each edge of the grammar: an
// accepted pair gives its canonical host:port.
func TestJoinTargetGivesOneSpelling(t *testing.T) {
	long := strings.Repeat("a", 63)
	name253 := strings.Repeat(long+".", 3) + strings.Repeat("b", 61)
	for _, tc := range []struct{ host, port, want string }{
		{"192.0.2.10", "22", "192.0.2.10:22"},
		{"2001:0db8:0::1", "22", "[2001:db8::1]:22"},
		{"FE80::1%eth0", "22", "[fe80::1%eth0]:22"},
		{"fe80::1%Eth0.100", "22", "[fe80::1%Eth0.100]:22"},
		{"fe80::1%2", "22", "[fe80::1%2]:22"},
		{"::ffff:192.0.2.10", "22", "192.0.2.10:22"},
		{"::ffff:c000:20a", "22", "192.0.2.10:22"},
		{"::ffff:192.0.2.10%eth0", "22", "192.0.2.10:22"},
		{"Device.Example.TEST.", "22", "device.example.test:22"},
		{"device.example.test", "1", "device.example.test:1"},
		{"device.example.test", "65535", "device.example.test:65535"},
		{"device.example.test", "022", "device.example.test:22"},
		{"192.0.2.10", "08443", "192.0.2.10:8443"},
		{"device.example.test", "0000065535", "device.example.test:65535"},
		{"_ssh.example.test", "22", "_ssh.example.test:22"},
		{"ssh_1.example.test", "22", "ssh_1.example.test:22"},
		{"ssh_.example.test", "22", "ssh_.example.test:22"},
		{"a-b.example.test", "22", "a-b.example.test:22"},
		{long + ".example.test", "22", long + ".example.test:22"},
		{name253, "22", name253 + ":22"},
		{name253 + ".", "22", name253 + ":22"},
		{"device", "22", "device:22"},
	} {
		got, err := JoinTarget(tc.host, tc.port)
		if err != nil || got != tc.want {
			t.Errorf("JoinTarget(%q, %q) = %q, %v, want %q", tc.host, tc.port, got, err, tc.want)
		}
	}
}

// TestJoinTargetRefusesWhatIsNoTarget joins hosts and ports one step past each edge:
// each is ErrInvalidTarget.
func TestJoinTargetRefusesWhatIsNoTarget(t *testing.T) {
	long := strings.Repeat("a", 64)
	name254 := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 62)
	for _, tc := range []struct{ host, port string }{
		{"fe80::1%", "22"}, {"fe80::1%a]b", "22"}, {"fe80::1%a%b", "22"}, {"fe80::1%a b", "22"},
		{"fe80::1%-eth0", "22"}, {"192.0.2.10%eth0", "22"}, {"[2001:db8::1]", "22"}, {"", "22"}, {".", "22"},
		{"-device.example.test", "22"}, {"device-.example.test", "22"}, {"a..b", "22"}, {".a", "22"},
		{long + ".example.test", "22"}, {name254, "22"}, {name254 + ".", "22"}, {"a b", "22"}, {"dévice", "22"},
		{"device.example.test", "0"}, {"device.example.test", "000"}, {"device.example.test", "65536"},
		{"device.example.test", "065536"}, {"device.example.test", "+22"}, {"device.example.test", "-22"},
		{"device.example.test", ""}, {"device.example.test", "2_2"}, {"device.example.test", " 22"},
		{"device.example.test", "0x16"}, {"device.example.test", "x"},
	} {
		if got, err := JoinTarget(tc.host, tc.port); !errors.Is(err, ErrInvalidTarget) || got != "" {
			t.Errorf("JoinTarget(%q, %q) = %q, %v, want ErrInvalidTarget", tc.host, tc.port, got, err)
		}
	}
}

// TestLabelRuneTakesTheLabelAlphabet reads every ASCII rune: only letters, digits, '_'
// and '-' belong to a label.
func TestLabelRuneTakesTheLabelAlphabet(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	for r := range rune(0x80) {
		if got, want := labelRune(r), strings.ContainsRune(alphabet, r); got != want {
			t.Errorf("labelRune(%q) = %t, want %t", r, got, want)
		}
	}
}

// TestParseTargetSplitsHostAndPort reads -ssh-target texts: IPv6 needs its brackets,
// and every refusal quotes the text.
func TestParseTargetSplitsHostAndPort(t *testing.T) {
	for raw, want := range map[string]string{
		"[2001:db8::1]:22":       "[2001:db8::1]:22",
		"[fe80::1%eth0]:22":      "[fe80::1%eth0]:22",
		"[::ffff:192.0.2.10]:22": "192.0.2.10:22",
		"192.0.2.10:2222":        "192.0.2.10:2222",
		"[2001:db8::1]:022":      "[2001:db8::1]:22",
		"device.example.test:22": "device.example.test:22",
	} {
		if got, err := parseTarget(raw); err != nil || got != want {
			t.Errorf("parseTarget(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"2001:db8::1:22", "device.example.test", "[fe80::1%]:22", "device:0"} {
		got, err := parseTarget(raw)
		if want := strconv.Quote(raw) + " is an invalid target"; !errors.Is(err, ErrInvalidTarget) ||
			err.Error() != want || got != "" {
			t.Errorf("parseTarget(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
}

// TestListenAddressReadsHostAndPort reads listen addresses at the edges of their
// grammar: an IP literal or no host and a port from 1 to 65535, which loses its leading
// zeros.
func TestListenAddressReadsHostAndPort(t *testing.T) {
	for raw, want := range map[string]string{
		":1": ":1", "0.0.0.0:65535": "0.0.0.0:65535", "[::]:8443": "[::]:8443",
		"[fe80::1%eth0]:8443": "[fe80::1%eth0]:8443", "127.0.0.1:8080": "127.0.0.1:8080",
		"127.0.0.1:08443": "127.0.0.1:8443", "[::]:008443": "[::]:8443",
	} {
		if got, err := listenAddress(raw); err != nil || got != want {
			t.Errorf("listenAddress(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"localhost:8443", "8443", "127.0.0.1:0", "127.0.0.1:000", "127.0.0.1:65536", "127.0.0.1:x",
		"127.0.0.1:+8443", "127.0.0.1:", "",
	} {
		if got, err := listenAddress(raw); !errors.Is(err, errListenAddress) || got != "" {
			t.Errorf("listenAddress(%q) = %q, %v, want errListenAddress", raw, got, err)
		}
	}
}

// referenceLabel matches a DNS label of the target grammar: ASCII letters, digits,
// '_' and inner '-', 1 to 63 bytes.
var referenceLabel = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// referenceDigits matches a port of the target grammar, decimal digits, and captures
// them without their leading zeros.
var referenceDigits = regexp.MustCompile(`^0*([1-9]\d{0,4})$`)

// referenceTarget returns what the grammar of a target makes of host and port, written
// without the package: the canonical host:port and whether the pair is a target.
func referenceTarget(host, port string) (string, bool) {
	number, portRead := referencePort(port)
	if canonical, ok, isIP := referenceIP(host); isIP {
		return net.JoinHostPort(canonical, number), portRead && ok
	}
	name := strings.TrimSuffix(host, ".")
	return net.JoinHostPort(strings.ToLower(name), number), portRead && referenceName(name)
}

// referencePort returns port without its leading zeros and whether it is decimal digits
// whose value is 1 to 65535.
func referencePort(port string) (string, bool) {
	m := referenceDigits.FindStringSubmatch(port)
	if m == nil {
		return "", false
	}
	n, err := strconv.Atoi(m[1])
	return m[1], err == nil && n <= 65535
}

// referenceIP reads host as net.ParseIP does once its zone is cut off: whether it is an
// IP address, its canonical spelling, and whether its zone, when it has one, is a name
// on IPv6.
func referenceIP(host string) (canonical string, ok, isIP bool) {
	text, zone, zoned := strings.Cut(host, "%")
	ip := net.ParseIP(text)
	switch {
	case ip == nil:
		return "", false, false
	case !zoned:
		return ip.String(), true, true
	case ip.To4() != nil:
		return ip.To4().String(), strings.Contains(text, ":") && referenceName(zone), true
	}
	return ip.String() + "%" + zone, referenceName(zone), true
}

// referenceName reports whether name is 1 to 253 bytes of labels referenceLabel
// matches.
func referenceName(name string) bool {
	labels := strings.Split(name, ".")
	return name != "" && len(name) <= 253 && !slices.ContainsFunc(labels, func(label string) bool {
		return !referenceLabel.MatchString(label)
	})
}

// FuzzJoinTarget compares JoinTarget with referenceTarget on any host and port, and
// requires an accepted target to join to itself again.
func FuzzJoinTarget(f *testing.F) {
	for _, seed := range [][2]string{
		{"192.0.2.10", "22"}, {"2001:0db8::1", "65535"}, {"Device.Example.TEST.", "1"}, {"_a-b_", "022"}, {"a", "000"},
		{"fe80::1%eth0", "22"}, {"::ffff:192.0.2.1", "22"}, {"::ffff:192.0.2.1%eth0", "22"}, {"fe80::1%a]b", "22"},
		{"192.0.2.1%eth0", "22"}, {"fe80::1%", "22"}, {"a..b", "0"}, {"", "+1"}, {"-a", "65536"}, {"a", "0065536"},
		{"a", "-1"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, host, port string) {
		got, err := JoinTarget(host, port)
		want, ok := referenceTarget(host, port)
		if ok != (err == nil) || ok && got != want || !ok && !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("JoinTarget(%q, %q) = %q, %v, want %q, accepted %v", host, port, got, err, want, ok)
		}
		if ok {
			checkJoinsAgain(t, got)
		}
	})
}

// checkJoinsAgain fails t unless target, a canonical host:port, joins to itself.
func checkJoinsAgain(t *testing.T, target string) {
	t.Helper()
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) = %v, want nil", target, err)
	}
	if again, err := JoinTarget(h, p); err != nil || again != target {
		t.Fatalf("JoinTarget(%q, %q) = %q, %v, want %q", h, p, again, err, target)
	}
}
