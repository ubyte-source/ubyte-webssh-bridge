package config

import (
	"crypto/tls"
	"fmt"
	"time"
)

// Configuration defines the complete set of parameters for the WebSSH bridge server.
type Configuration struct {
	// ListenAddress is the network address the server will listen on (e.g., ":8080").
	ListenAddress string
	// CertificateFile is the path to the TLS certificate.
	CertificateFile string
	// KeyFile is the path to the TLS private key.
	KeyFile string
	// DebugMode enables verbose logging for development and troubleshooting.
	DebugMode bool

	// MaxConnections is the maximum number of concurrent connections allowed.
	MaxConnections int
	// MaxConnectionsPerHost is the maximum number of connections from a single IP address.
	MaxConnectionsPerHost int
	// ConnectionTimeout is the maximum duration for a connection to be idle.
	ConnectionTimeout time.Duration

	// SSHConnectTimeout is the timeout for establishing the initial SSH connection.
	SSHConnectTimeout time.Duration
	// SSHAuthTimeout is the timeout for completing SSH authentication.
	SSHAuthTimeout time.Duration
	// SSHHandshakeTimeout is the timeout for the SSH handshake process.
	SSHHandshakeTimeout time.Duration

	// WebSocketReadBufferSize is the size of the read buffer for WebSocket connections.
	WebSocketReadBufferSize int
	// WebSocketWriteBufferSize is the size of the write buffer for WebSocket connections.
	WebSocketWriteBufferSize int
	// WebSocketHandshakeTimeout is the timeout for the WebSocket handshake.
	WebSocketHandshakeTimeout time.Duration
	// WebSocketReadLimit is the maximum message size allowed from a client.
	WebSocketReadLimit int64

	// RateLimitInterval is the time window for the rate limiter.
	RateLimitInterval time.Duration
	// RateLimitBurst is the number of requests allowed within the interval.
	RateLimitBurst int
	// RateLimitPerIP enables per-IP address rate limiting.
	RateLimitPerIP bool
	// RateLimitWhitelist is a list of IP addresses to exclude from rate limiting.
	RateLimitWhitelist []string

	// EnableHealthCheck enables the health check endpoint.
	EnableHealthCheck bool
	// HealthCheckPath defines the URL path for the health check endpoint.
	HealthCheckPath string
	// EnableMetrics enables the metrics endpoint.
	EnableMetrics bool
	// MetricsPath defines the URL path for the metrics endpoint.
	MetricsPath string

	// ShutdownTimeout is the duration to wait for graceful server shutdown.
	ShutdownTimeout time.Duration

	// TLSConfig holds the TLS configuration for the server.
	TLSConfig *tls.Config
}

// DefaultConfiguration creates a new Configuration instance with sensible default values.
// These defaults are suitable for a development environment but should be reviewed
// and adjusted for production use.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		ListenAddress:             "127.0.0.1:8080",
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
		WebSocketReadLimit:        512 * 1024, // 512 KB
		RateLimitInterval:         2 * time.Second,
		RateLimitBurst:            10,
		RateLimitPerIP:            true,
		RateLimitWhitelist:        []string{},
		EnableHealthCheck:         true,
		HealthCheckPath:           "/health",
		EnableMetrics:             false,
		MetricsPath:               "/metrics",
		ShutdownTimeout:           30 * time.Second,
	}
}

// Validate checks the configuration for common errors, such as empty or non-positive values.
// It ensures that the configuration is sane before the server attempts to use it.
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
	if c.ConnectionTimeout <= 0 {
		return fmt.Errorf("connection timeout must be positive")
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
	if c.WebSocketHandshakeTimeout <= 0 {
		return fmt.Errorf("websocket handshake timeout must be positive")
	}
	if c.WebSocketReadLimit <= 0 {
		return fmt.Errorf("websocket read limit must be positive")
	}
	if c.RateLimitInterval <= 0 {
		return fmt.Errorf("rate limit interval must be positive")
	}
	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("rate limit burst must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}
	return nil
}

// SecureTLSConfig returns a *tls.Config with modern, secure settings.
// It enforces TLS 1.2 as the minimum version and selects a strong set of cipher suites.
func SecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}
