package config

import (
	"crypto/tls"
	"net/netip"
	"slices"
	"time"
)

// ServerConfig holds the TLS listener: its certificate pair, the proxies it trusts to
// name the client, its address, the time the sessions have to end at a stop, and the
// debug records.
type ServerConfig struct {
	Certificate     tls.Certificate // the pair loaded from CertFile and KeyFile
	TrustedProxies  []netip.Prefix  // masked and unmapped, at most 64
	Address         string
	CertFile        string
	KeyFile         string
	ShutdownTimeout time.Duration
	Debug           bool
}

// ConnConfig holds the caps on concurrent sessions: of the process and per target.
type ConnConfig struct {
	MaxTotal   int
	MaxPerHost int
}

// RateConfig holds the bound on new sessions per client address: Burst at once, all
// of them regained within Interval.
type RateConfig struct {
	Burst    int
	Interval time.Duration
}

// WSConfig holds the time a client has to send its request headers and its connect
// message.
type WSConfig struct {
	HandshakeTimeout time.Duration
}

// Config is the loaded configuration: one field per block of settings.
type Config struct {
	Server ServerConfig
	Conn   ConnConfig
	Rate   RateConfig
	SSH    SSHConfig
	WS     WSConfig
	unread []string // UWSB_ variables with a value that no setting reads, in name order
}

// UnreadNames returns, in name order, the UWSB_ variables with a value that no
// setting reads, in a slice the caller owns.
func (c *Config) UnreadNames() []string {
	return slices.Clone(c.unread)
}
