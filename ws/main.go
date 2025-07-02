package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/server"
)

var (
	// Server settings
	debugMode       *bool
	listenAddress   *string
	certificateFile *string
	keyFile         *string

	// Connection limits
	maxConnections        *int
	maxConnectionsPerHost *int
	connectionTimeout     *string

	// SSH settings
	sshConnectTimeout   *string
	sshAuthTimeout      *string
	sshHandshakeTimeout *string

	// WebSocket settings
	wsReadBufferSize   *int
	wsWriteBufferSize  *int
	wsHandshakeTimeout *string
	wsReadLimit        *int64

	// Rate limiting
	rateLimitInterval  *string
	rateLimitBurst     *int
	rateLimitPerIP     *bool
	rateLimitWhitelist *string

	// Monitoring
	enableHealthCheck *bool
	healthCheckPath   *string
	enableMetrics     *bool
	metricsPath       *string

	// Server behavior
	shutdownTimeout *string
)

// init defines and parses command-line flags for application configuration.
// Flags are organized by category for clarity.
func init() {
	// Connection settings
	connectionTimeout = flag.String("conn-timeout", "", "Connection timeout duration (e.g., '30s', '1m'). Overrides UWSB_CONN_TIMEOUT.")
	maxConnections = flag.Int("conn-max-total", 0, "Maximum number of concurrent connections. Overrides UWSB_CONN_MAX_TOTAL.")
	maxConnectionsPerHost = flag.Int("conn-max-per-host", 0, "Maximum number of concurrent connections per source IP. Overrides UWSB_CONN_MAX_PER_HOST.")

	// Health and metrics monitoring
	enableHealthCheck = flag.Bool("health-enabled", true, "Enable the /health endpoint. Overrides UWSB_HEALTH_ENABLED.")
	healthCheckPath = flag.String("health-path", "/health", "Path for the health check endpoint. Overrides UWSB_HEALTH_PATH.")
	enableMetrics = flag.Bool("metrics-enabled", false, "Enable the /metrics endpoint. Overrides UWSB_METRICS_ENABLED.")
	metricsPath = flag.String("metrics-path", "/metrics", "Path for the metrics endpoint. Overrides UWSB_METRICS_PATH.")

	// Rate limiting settings
	rateLimitBurst = flag.Int("rate-burst", 0, "Number of requests allowed in a burst. Overrides UWSB_RATE_BURST.")
	rateLimitInterval = flag.String("rate-interval", "", "Time interval for the rate limit bucket. Overrides UWSB_RATE_INTERVAL.")
	rateLimitPerIP = flag.Bool("rate-per-ip", true, "Apply rate limiting on a per-IP basis. Overrides UWSB_RATE_PER_IP.")
	rateLimitWhitelist = flag.String("rate-whitelist", "", "Comma-separated list of IPs to exclude from rate limiting. Overrides UWSB_RATE_WHITELIST.")

	// Server settings
	listenAddress = flag.String("server-address", ":8080", "The address for the server to listen on. Overrides UWSB_SERVER_ADDRESS.")
	certificateFile = flag.String("server-cert", "", "Path to the TLS certificate file. Overrides UWSB_SERVER_CERT_FILE.")
	debugMode = flag.Bool("server-debug", false, "Enable debug mode for verbose logging. Overrides UWSB_SERVER_DEBUG.")
	keyFile = flag.String("server-key", "", "Path to the TLS private key file. Overrides UWSB_SERVER_KEY_FILE.")
	shutdownTimeout = flag.String("server-shutdown-timeout", "30s", "Graceful shutdown timeout. Overrides UWSB_SERVER_SHUTDOWN_TIMEOUT.")

	// SSH settings
	sshAuthTimeout = flag.String("ssh-auth-timeout", "45s", "Timeout for SSH authentication. Overrides UWSB_SSH_AUTH_TIMEOUT.")
	sshConnectTimeout = flag.String("ssh-connect-timeout", "10s", "Timeout for establishing an SSH connection. Overrides UWSB_SSH_CONNECT_TIMEOUT.")
	sshHandshakeTimeout = flag.String("ssh-handshake-timeout", "60s", "Timeout for the SSH handshake. Overrides UWSB_SSH_HANDSHAKE_TIMEOUT.")

	// WebSocket settings
	wsHandshakeTimeout = flag.String("ws-handshake-timeout", "30s", "Timeout for the WebSocket handshake. Overrides UWSB_WS_HANDSHAKE_TIMEOUT.")
	wsReadBufferSize = flag.Int("ws-read-buffer", 8192, "Read buffer size for WebSocket connections. Overrides UWSB_WS_READ_BUFFER.")
	wsReadLimit = flag.Int64("ws-read-limit", 512*1024, "Maximum message size in bytes for WebSocket connections. Overrides UWSB_WS_READ_LIMIT.")
	wsWriteBufferSize = flag.Int("ws-write-buffer", 8192, "Write buffer size for WebSocket connections. Overrides UWSB_WS_WRITE_BUFFER.")
}

// main is the application's entry point. It initializes the configuration,
// creates the server instance, and starts the service.
func main() {
	flag.Parse()

	cfg := config.DefaultConfiguration()
	applyConfig(cfg)

	bridge, err := server.NewWebSSHBridge(cfg)
	if err != nil {
		log.Fatalf("Failed to create WebSSH bridge: %v", err)
	}

	if err := bridge.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// configResolver provides consistent flag and environment variable resolution
type configResolver struct{}

// getString retrieves a string value, preferring the flag over the environment variable
func (r configResolver) getString(flagValue *string, envKey string, fallback string) string {
	if flagValue != nil && *flagValue != "" {
		return *flagValue
	}
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return fallback
}

// getInt retrieves an integer value, preferring the flag over the environment variable
func (r configResolver) getInt(flagValue *int, envKey string, fallback int) int {
	if flagValue != nil && *flagValue > 0 {
		return *flagValue
	}
	if value := os.Getenv(envKey); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

// getInt64 retrieves an int64 value, preferring the flag over the environment variable
func (r configResolver) getInt64(flagValue *int64, envKey string, fallback int64) int64 {
	if flagValue != nil && *flagValue > 0 {
		return *flagValue
	}
	if value := os.Getenv(envKey); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

// getBool retrieves a boolean value, preferring the flag over the environment variable
func (r configResolver) getBool(flagValue *bool, envKey string, fallback bool) bool {
	if flagValue != nil {
		return *flagValue
	}
	if value := os.Getenv(envKey); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return fallback
}

// getDuration retrieves a time.Duration value, preferring the flag over the environment variable
func (r configResolver) getDuration(flagValue *string, envKey string, fallback time.Duration) time.Duration {
	var value string
	if flagValue != nil && *flagValue != "" {
		value = *flagValue
	} else {
		value = os.Getenv(envKey)
	}

	if value == "" {
		return fallback
	}

	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed
	}
	return fallback
}

// getStringSlice retrieves a slice of strings, preferring the flag over the environment variable
func (r configResolver) getStringSlice(flagValue *string, envKey string, fallback []string) []string {
	var value string
	if flagValue != nil && *flagValue != "" {
		value = *flagValue
	} else {
		value = os.Getenv(envKey)
	}

	if value == "" {
		return fallback
	}

	return strings.Split(strings.TrimSpace(value), ",")
}

// applyConfig populates the configuration struct from command-line flags and
// environment variables. Command-line flags take precedence over environment variables.
func applyConfig(cfg *config.Configuration) {
	resolver := configResolver{}

	// Server configuration
	cfg.ListenAddress = resolver.getString(listenAddress, "UWSB_SERVER_ADDRESS", cfg.ListenAddress)
	cfg.CertificateFile = resolver.getString(certificateFile, "UWSB_SERVER_CERT_FILE", cfg.CertificateFile)
	cfg.KeyFile = resolver.getString(keyFile, "UWSB_SERVER_KEY_FILE", cfg.KeyFile)
	cfg.DebugMode = resolver.getBool(debugMode, "UWSB_SERVER_DEBUG", cfg.DebugMode)
	cfg.ShutdownTimeout = resolver.getDuration(shutdownTimeout, "UWSB_SERVER_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout)

	// Connection configuration
	cfg.MaxConnections = resolver.getInt(maxConnections, "UWSB_CONN_MAX_TOTAL", cfg.MaxConnections)
	cfg.MaxConnectionsPerHost = resolver.getInt(maxConnectionsPerHost, "UWSB_CONN_MAX_PER_HOST", cfg.MaxConnectionsPerHost)
	cfg.ConnectionTimeout = resolver.getDuration(connectionTimeout, "UWSB_CONN_TIMEOUT", cfg.ConnectionTimeout)

	// SSH configuration
	cfg.SSHConnectTimeout = resolver.getDuration(sshConnectTimeout, "UWSB_SSH_CONNECT_TIMEOUT", cfg.SSHConnectTimeout)
	cfg.SSHAuthTimeout = resolver.getDuration(sshAuthTimeout, "UWSB_SSH_AUTH_TIMEOUT", cfg.SSHAuthTimeout)
	cfg.SSHHandshakeTimeout = resolver.getDuration(sshHandshakeTimeout, "UWSB_SSH_HANDSHAKE_TIMEOUT", cfg.SSHHandshakeTimeout)

	// WebSocket configuration
	cfg.WebSocketReadBufferSize = resolver.getInt(wsReadBufferSize, "UWSB_WS_READ_BUFFER", cfg.WebSocketReadBufferSize)
	cfg.WebSocketWriteBufferSize = resolver.getInt(wsWriteBufferSize, "UWSB_WS_WRITE_BUFFER", cfg.WebSocketWriteBufferSize)
	cfg.WebSocketHandshakeTimeout = resolver.getDuration(wsHandshakeTimeout, "UWSB_WS_HANDSHAKE_TIMEOUT", cfg.WebSocketHandshakeTimeout)
	cfg.WebSocketReadLimit = resolver.getInt64(wsReadLimit, "UWSB_WS_READ_LIMIT", cfg.WebSocketReadLimit)

	// Rate limiting configuration
	cfg.RateLimitInterval = resolver.getDuration(rateLimitInterval, "UWSB_RATE_INTERVAL", cfg.RateLimitInterval)
	cfg.RateLimitBurst = resolver.getInt(rateLimitBurst, "UWSB_RATE_BURST", cfg.RateLimitBurst)
	cfg.RateLimitPerIP = resolver.getBool(rateLimitPerIP, "UWSB_RATE_PER_IP", cfg.RateLimitPerIP)
	cfg.RateLimitWhitelist = resolver.getStringSlice(rateLimitWhitelist, "UWSB_RATE_WHITELIST", cfg.RateLimitWhitelist)

	// Monitoring configuration
	cfg.EnableHealthCheck = resolver.getBool(enableHealthCheck, "UWSB_HEALTH_ENABLED", cfg.EnableHealthCheck)
	cfg.HealthCheckPath = resolver.getString(healthCheckPath, "UWSB_HEALTH_PATH", cfg.HealthCheckPath)
	cfg.EnableMetrics = resolver.getBool(enableMetrics, "UWSB_METRICS_ENABLED", cfg.EnableMetrics)
	cfg.MetricsPath = resolver.getString(metricsPath, "UWSB_METRICS_PATH", cfg.MetricsPath)
}
