package config

import (
	"crypto/tls"
	"fmt"
)

// validate records each rule among settings that c, the loaded Config, breaks, once
// -ssh-target reads: with a target, -conn-max-per-host is not set; without one, it is
// at most -conn-max-total, and the listener stays on loopback.
func (l *loader) validate(c *Config) {
	target := l.setting(&c.SSH.Target)
	if target.failed {
		return
	}
	perHost, total := l.setting(&c.Conn.MaxPerHost), l.setting(&c.Conn.MaxTotal)
	if c.SSH.Target != "" {
		if perHost.given {
			l.fail(perHost, fmt.Errorf("%w while %s pins one target, whose cap is %s", errPerHostWithTarget,
				target.names(), total.names()))
		}
		return
	}
	if !perHost.failed && !total.failed && c.Conn.MaxPerHost > c.Conn.MaxTotal {
		l.fail(perHost, fmt.Errorf("%d %w %s, %d", c.Conn.MaxPerHost, errPerHostOverTotal, total.names(),
			c.Conn.MaxTotal))
	}
	if address := l.setting(&c.Server.Address); !address.failed && !loopbackListener(c.Server.Address) {
		l.fail(address, fmt.Errorf("%q %w while %s is empty, so any client could name any host",
			c.Server.Address, errOpenRelay, target.names()))
	}
}

// loadCertificate loads the TLS pair of the files of s into s, or records the problem
// of the two files.
func (l *loader) loadCertificate(s *ServerConfig) {
	pair, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		names := l.setting(&s.CertFile).names() + " and " + l.setting(&s.KeyFile).names()
		l.problems = append(l.problems, newProblem(names, fmt.Errorf("%w: %w", errCertificate, err)))
		return
	}
	s.Certificate = pair
}
