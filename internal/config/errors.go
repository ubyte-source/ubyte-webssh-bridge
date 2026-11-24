package config

import (
	"errors"
	"fmt"
)

// Requests of the command line for something other than a run.
var (
	// ErrHelp reports that -h or -help asks for the usage, which Load writes.
	ErrHelp = errors.New("help requested")
	// ErrVersionRequested reports that -version asks for the version and an exit.
	ErrVersionRequested = errors.New("version requested")
	// ErrHealthRequested reports that -health asks for a probe of the listen address;
	// Load returns it beside the Config.
	ErrHealthRequested = errors.New("health check requested")
)

// ErrInvalidConfig reports a configuration to fix; every problem Load returns is it.
var ErrInvalidConfig = errors.New("invalid configuration")

// ErrInvalidTarget reports a host or port that is not a target: JoinTarget's only
// failure.
var ErrInvalidTarget = errors.New("invalid target")

// The causes of the problems, each written after the value it concerns when it has
// one.
var (
	errNotInteger        = errors.New("is not a base 10 integer")
	errNotBool           = errors.New("is not a bool")
	errNotDuration       = errors.New("is not a duration")
	errOutOfRange        = errors.New("is outside")
	errListenAddress     = errors.New("is not host:port with an IP or no host and a port from 1 to 65535")
	errTrustedProxy      = errors.New("is not an IP address or a CIDR prefix without a zone")
	errTooManyProxies    = errors.New("entries are more than")
	errPerHostWithTarget = errors.New("set")
	errPerHostOverTotal  = errors.New("is more than")
	errOpenRelay         = errors.New("listens beyond loopback")
	errCertificate       = errors.New("do not load as a TLS pair")
	errCommandLine       = errors.New("is an unknown flag, a flag without its value or a malformed flag")
	errArgument          = errors.New("is not a flag: " + commandName + " takes no argument")
)

// problem is a configuration to fix: it reads and unwraps as its cause and is
// ErrInvalidConfig.
type problem struct {
	cause error
}

// newProblem returns the problem of names, the flag and the variable it concerns or
// the command line, whose cause is rule.
func newProblem(names string, rule error) error {
	return problem{cause: fmt.Errorf("%s: %w", names, rule)}
}

// Error returns the text of the cause.
func (p problem) Error() string {
	return p.cause.Error()
}

// Unwrap returns the cause.
func (p problem) Unwrap() error {
	return p.cause
}

// Is reports whether target is ErrInvalidConfig.
func (problem) Is(target error) bool {
	return target == ErrInvalidConfig
}
