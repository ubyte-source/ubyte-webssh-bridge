package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/connection"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"github.com/ubyte-source/ubyte-webssh-bridge/utils"
)

// WebSSHBridge encapsulates the server's state, including its configuration,
// logger, and managers for connections and rate limiting.
type WebSSHBridge struct {
	config            *config.Configuration
	logger            *logrus.Logger
	connectionManager *connection.ConnectionManager
	rateLimiter       *utils.RateLimiter
	httpServer        *http.Server
	websocketUpgrader websocket.Upgrader
}

// NewWebSSHBridge creates and initializes a new WebSSHBridge instance.
// It validates the provided configuration and sets up the logger, connection manager,
// rate limiter, and WebSocket upgrader.
func NewWebSSHBridge(cfg *config.Configuration) (*WebSSHBridge, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	logger := logrus.New()
	if cfg.DebugMode {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	connectionManager := connection.NewConnectionManager(cfg, logger)
	rateLimiter := utils.NewRateLimiter(
		cfg.RateLimitInterval,
		cfg.RateLimitBurst,
		cfg.RateLimitPerIP,
		cfg.RateLimitWhitelist,
	)

	server := &WebSSHBridge{
		config:            cfg,
		logger:            logger,
		connectionManager: connectionManager,
		rateLimiter:       rateLimiter,
	}

	server.websocketUpgrader = websocket.Upgrader{
		ReadBufferSize:   cfg.WebSocketReadBufferSize,
		WriteBufferSize:  cfg.WebSocketWriteBufferSize,
		HandshakeTimeout: cfg.WebSocketHandshakeTimeout,
		CheckOrigin:      server.checkOrigin,
	}

	return server, nil
}

// Start configures and starts the HTTP server, including routing and TLS.
// It blocks until the server is shut down.
func (bridge *WebSSHBridge) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/", bridge.handleWebSocket)

	if bridge.config.EnableHealthCheck {
		mux.HandleFunc(bridge.config.HealthCheckPath, bridge.handleHealthCheck)
	}
	if bridge.config.EnableMetrics {
		mux.HandleFunc(bridge.config.MetricsPath, bridge.handleMetrics)
	}

	bridge.httpServer = &http.Server{
		Addr:      bridge.config.ListenAddress,
		Handler:   mux,
		TLSConfig: config.SecureTLSConfig(),
	}

	bridge.logger.Infof("Starting WebSSH Bridge server on %s", bridge.config.ListenAddress)
	if err := bridge.httpServer.ListenAndServeTLS(bridge.config.CertificateFile, bridge.config.KeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %v", err)
	}

	return nil
}

// Stop gracefully shuts down the server, closing all active components.
func (bridge *WebSSHBridge) Stop() error {
	bridge.logger.Info("Shutting down WebSSH Bridge server...")

	ctx, cancel := context.WithTimeout(context.Background(), bridge.config.ShutdownTimeout)
	defer cancel()

	if err := bridge.httpServer.Shutdown(ctx); err != nil {
		bridge.logger.Errorf("HTTP server shutdown error: %v", err)
	}

	if err := bridge.connectionManager.Shutdown(); err != nil {
		bridge.logger.Errorf("Connection manager shutdown error: %v", err)
	}

	bridge.rateLimiter.Close()

	bridge.logger.Info("WebSSH Bridge server shutdown complete")
	return nil
}

// checkOrigin performs a security check to prevent Cross-Site WebSocket Hijacking (CSWH).
// It ensures that the WebSocket connection's origin matches the server's host.
func (bridge *WebSSHBridge) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Allow non-browser clients
	}
	host := r.Host
	if origin != "https://"+host && origin != "http://"+host {
		bridge.logger.Warnf("WebSocket connection from untrusted origin %s blocked (host: %s)", origin, host)
		return false
	}
	return true
}

// handleWebSocket manages the entire lifecycle of a WebSocket connection.
// It handles rate limiting, upgrades the connection, creates a session, and bridges
// communication between the WebSocket and the SSH server.
func (bridge *WebSSHBridge) handleWebSocket(responseWriter http.ResponseWriter, request *http.Request) {
	targetAddress, err := bridge.connectionManager.ParseTargetAddress(request)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	clientIP := bridge.connectionManager.GetClientIP(request)
	if !bridge.rateLimiter.IsAllowed(clientIP) {
		http.Error(responseWriter, "Rate limit exceeded. Please wait before trying again", http.StatusTooManyRequests)
		bridge.logger.Warnf("Rate limit exceeded for IP %s connecting to %s", clientIP, targetAddress)
		return
	}

	webSocketConn, err := bridge.websocketUpgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		bridge.logger.Errorf("WebSocket upgrade error: %v", err)
		return
	}
	defer func() {
		if err := webSocketConn.Close(); err != nil {
			bridge.logger.Errorf("Failed to close WebSocket connection: %v", err)
		}
	}()

	webSocketConn.SetReadLimit(bridge.config.WebSocketReadLimit)

	session, err := bridge.connectionManager.CreateSession(webSocketConn, targetAddress, clientIP)
	if err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to create session", err)
		return
	}

	credentials, err := bridge.readSSHCredentials(webSocketConn)
	if err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to read SSH credentials", err)
		if removeErr := bridge.connectionManager.RemoveSession(session.ID); removeErr != nil {
			bridge.logger.Errorf("Failed to remove session %s after credentials error: %v", session.ID, removeErr)
		}
		return
	}

	if err := bridge.connectionManager.InitializeSession(session, credentials); err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to initialize SSH connection", err)
		return
	}

	bridge.logger.Infof("WebSocket session %s established: %s -> %s", session.ID, clientIP, targetAddress)

	if err := session.WaitForCompletion(); err != nil {
		bridge.logger.Debugf("SSH session %s completed with error: %v", session.ID, err)
	}

	if removeErr := bridge.connectionManager.RemoveSession(session.ID); removeErr != nil {
		bridge.logger.Errorf("Failed to remove session %s after completion: %v", session.ID, removeErr)
	}
}

// handleHealthCheck provides a simple health status of the server.
func (bridge *WebSSHBridge) handleHealthCheck(responseWriter http.ResponseWriter, request *http.Request) {
	stats := bridge.connectionManager.GetStats()
	health := map[string]interface{}{
		"status":          "healthy",
		"timestamp":       time.Now().UTC(),
		"active_sessions": stats["active_sessions"],
		"total_sessions":  stats["total_sessions"],
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(responseWriter).Encode(health); err != nil {
		bridge.logger.Errorf("Failed to encode health check response: %v", err)
		http.Error(responseWriter, "Internal server error", http.StatusInternalServerError)
	}
}

// handleMetrics exposes performance and usage metrics.
func (bridge *WebSSHBridge) handleMetrics(responseWriter http.ResponseWriter, request *http.Request) {
	connectionStats := bridge.connectionManager.GetStats()
	rateLimiterStats := bridge.rateLimiter.GetStats()
	metrics := map[string]interface{}{
		"connections": connectionStats,
		"limiter":     rateLimiterStats,
		"timestamp":   time.Now().UTC(),
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(responseWriter).Encode(metrics); err != nil {
		bridge.logger.Errorf("Failed to encode metrics response: %v", err)
		http.Error(responseWriter, "Internal server error", http.StatusInternalServerError)
	}
}

// readSSHCredentials reads the initial JSON message from the client, which
// contains the SSH credentials.
func (bridge *WebSSHBridge) readSSHCredentials(webSocketConn *websocket.Conn) (message.Credentials, error) {
	_, initialMessage, err := webSocketConn.ReadMessage()
	if err != nil {
		return message.Credentials{}, fmt.Errorf("error reading initial message: %v", err)
	}

	var credentials message.Credentials
	if err := json.Unmarshal(initialMessage, &credentials); err != nil {
		return message.Credentials{}, fmt.Errorf("error unmarshalling credentials: %v", err)
	}

	return credentials, nil
}

// handleWebSocketError logs an error and ensures the WebSocket connection is closed.
func (bridge *WebSSHBridge) handleWebSocketError(webSocketConn *websocket.Conn, errorMessage string, err error) {
	if closeErr := webSocketConn.Close(); closeErr != nil {
		bridge.logger.Errorf("Failed to close WebSocket after error: %v", closeErr)
	}
	bridge.logger.Errorf("%s: %v", errorMessage, err)
}

// Run starts the server and sets up a signal handler for graceful shutdown.
// It blocks until the server is terminated.
func (bridge *WebSSHBridge) Run() error {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	serverError := make(chan error, 1)
	go func() {
		serverError <- bridge.Start()
	}()

	select {
	case err := <-serverError:
		if err != nil {
			return fmt.Errorf("server error: %v", err)
		}
	case sig := <-signalChannel:
		bridge.logger.Infof("Received signal %v, initiating graceful shutdown", sig)
		return bridge.Stop()
	}

	return nil
}
