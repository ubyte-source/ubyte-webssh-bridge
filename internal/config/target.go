package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SSHConfig holds the SSH leg: the pinned target and the deadlines of the TCP
// connection and of the login.
type SSHConfig struct {
	Target         string // "" selects the path route
	ConnectTimeout time.Duration
	LoginTimeout   time.Duration
}

// The bounds of a DNS name and of its labels, and the base and the width of a port.
const (
	maxNameBytes  = 253
	maxLabelBytes = 63
	decimal       = 10
	portBits      = 16
)

// JoinTarget returns the canonical host:port of host, an IP literal or a DNS name, and
// port, decimal digits whose value is 1-65535, or ErrInvalidTarget.
func JoinTarget(host, port string) (string, error) {
	canonical, ok := canonicalHost(host)
	number, read := canonicalPort(port)
	if !ok || !read {
		return "", ErrInvalidTarget
	}
	return net.JoinHostPort(canonical, number), nil
}

// canonicalHost returns the one spelling of host and whether it is a target's host: an
// IP address, an IPv4-mapped one read as IPv4 and an IPv6 zone written as a DNS name,
// or a DNS name, which loses its final dot and its upper case.
func canonicalHost(host string) (string, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), addr.Zone() == "" || validName(addr.Zone())
	}
	name := strings.TrimSuffix(host, ".")
	return strings.ToLower(name), validName(name)
}

// validName reports whether name is 1 to 253 bytes of dot-separated labels.
func validName(name string) bool {
	if name == "" || len(name) > maxNameBytes {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

// validLabel reports whether label is 1 to 63 ASCII letters, digits, '_' and '-', no
// '-' first or last.
func validLabel(label string) bool {
	return label != "" && len(label) <= maxLabelBytes && !strings.HasPrefix(label, "-") &&
		!strings.HasSuffix(label, "-") && strings.TrimFunc(label, labelRune) == ""
}

func labelRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-'
}

// canonicalPort returns port without its leading zeros and whether port is decimal
// digits whose value is 1 to 65535.
func canonicalPort(port string) (string, bool) {
	n, err := strconv.ParseUint(port, decimal, portBits)
	return strconv.FormatUint(n, decimal), err == nil && n != 0
}

// parseTarget returns the canonical target of raw, host:port, or ErrInvalidTarget
// after raw.
func parseTarget(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", invalidTarget(raw)
	}
	target, err := JoinTarget(host, port)
	if err != nil {
		return "", invalidTarget(raw)
	}
	return target, nil
}

func invalidTarget(raw string) error {
	return fmt.Errorf("%q is an %w", raw, ErrInvalidTarget)
}

// listenAddress returns the listen address of raw, its port without leading zeros: an
// IP literal, or no host for every interface, and a port.
func listenAddress(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	number, read := canonicalPort(port)
	if err == nil && (host == "" || validIP(host)) && read {
		return net.JoinHostPort(host, number), nil
	}
	return "", fmt.Errorf(faultFormat, raw, errListenAddress)
}

func validIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// loopbackListener reports whether address listens on a loopback IP only.
func loopbackListener(address string) bool {
	ap, err := netip.ParseAddrPort(address)
	return err == nil && ap.Addr().IsLoopback()
}
