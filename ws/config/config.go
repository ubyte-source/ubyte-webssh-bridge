package config

import (
	"crypto/tls"
	"fmt"
	"time"
)

// Configuration holds all server configuration parameters
type Configuration struct {
	// Server settings
	ListenAddress   string
	CertificateFile string
	KeyFile         string
	DebugMode       bool

	// Connection limits
	MaxConnections        int
	MaxConnectionsPerHost int
	ConnectionTimeout     time.Duration

	// SSH settings
	SSHConnectTimeout   time.Duration
	SSHAuthTimeout      time.Duration
	SSHHandshakeTimeout time.Duration

	// WebSocket settings
	WebSocketReadBufferSize   int
	WebSocketWriteBufferSize  int
	WebSocketHandshakeTimeout time.Duration
	WebSocketReadLimit        int64

	// Rate limiting
	RateLimitInterval  time.Duration
	RateLimitBurst     int
	RateLimitPerIP     bool
	RateLimitWhitelist []string

	// Monitoring
	EnableHealthCheck bool
	HealthCheckPath   string
	EnableMetrics     bool
	MetricsPath       string

	// TLS settings
	TLSConfig *tls.Config
}

// DefaultConfiguration returns a configuration with sensible defaults
func DefaultConfiguration() *Configuration {
	return &Configuration{
		ListenAddress:             ":8080",
		CertificateFile:           "/data/certificate.crt",
		KeyFile:                   "/data/certificate.key",
		DebugMode:                 false,
		MaxConnections:            1000,
		MaxConnectionsPerHost:     10,
		ConnectionTimeout:         30 * time.Second,
		SSHConnectTimeout:         10 * time.Second,
		SSHAuthTimeout:            45 * time.Second,
		SSHHandshakeTimeout:       60 * time.Second,
		WebSocketReadBufferSize:   8192,
		WebSocketWriteBufferSize:  8192,
		WebSocketHandshakeTimeout: 30 * time.Second,
		WebSocketReadLimit:        512 * 1024,
		RateLimitInterval:         2 * time.Second,
		RateLimitBurst:            10,
		RateLimitPerIP:            true,
		RateLimitWhitelist:        []string{},
		EnableHealthCheck:         true,
		HealthCheckPath:           "/health",
		EnableMetrics:             false,
		MetricsPath:               "/metrics",
	}
}

// Validate checks if the configuration is valid
func (c *Configuration) Validate() error {
	if c.ListenAddress == "" {
		return fmt.Errorf("listen address cannot be empty")
	}

	if c.MaxConnections <= 0 {
		return fmt.Errorf("max connections must be positive")
	}

	if c.MaxConnectionsPerHost <= 0 {
		return fmt.Errorf("max connections per host must be positive")
	}

	if c.SSHConnectTimeout <= 0 {
		return fmt.Errorf("SSH connect timeout must be positive")
	}

	if c.SSHAuthTimeout <= 0 {
		return fmt.Errorf("SSH auth timeout must be positive")
	}

	if c.SSHHandshakeTimeout <= 0 {
		return fmt.Errorf("SSH handshake timeout must be positive")
	}

	return nil
}
