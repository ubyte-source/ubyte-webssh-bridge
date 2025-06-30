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

// WebSSHBridge represents the main server instance
type WebSSHBridge struct {
	config            *config.Configuration
	logger            *logrus.Logger
	connectionManager *connection.ConnectionManager
	rateLimiter       *utils.RateLimiter
	httpServer        *http.Server
	websocketUpgrader websocket.Upgrader
}

// NewWebSSHBridge creates a new WebSSH bridge server instance
func NewWebSSHBridge(cfg *config.Configuration) (*WebSSHBridge, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	// Setup logger
	logger := logrus.New()
	if cfg.DebugMode {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Create connection manager
	connectionManager := connection.NewConnectionManager(cfg, logger)

	// Create rate limiter
	rateLimiter := utils.NewRateLimiter(
		cfg.RateLimitInterval,
		cfg.RateLimitBurst,
		cfg.RateLimitPerIP,
		cfg.RateLimitWhitelist,
	)

	// Setup WebSocket upgrader
	upgrader := websocket.Upgrader{
		ReadBufferSize:   cfg.WebSocketReadBufferSize,
		WriteBufferSize:  cfg.WebSocketWriteBufferSize,
		HandshakeTimeout: cfg.WebSocketHandshakeTimeout,
		CheckOrigin:      func(r *http.Request) bool { return true },
	}

	server := &WebSSHBridge{
		config:            cfg,
		logger:            logger,
		connectionManager: connectionManager,
		rateLimiter:       rateLimiter,
		websocketUpgrader: upgrader,
	}

	return server, nil
}

// Start starts the WebSSH bridge server
func (bridge *WebSSHBridge) Start() error {
	// Setup HTTP server
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/ws/", bridge.handleWebSocket)

	if bridge.config.EnableHealthCheck {
		mux.HandleFunc(bridge.config.HealthCheckPath, bridge.handleHealthCheck)
	}

	if bridge.config.EnableMetrics {
		mux.HandleFunc(bridge.config.MetricsPath, bridge.handleMetrics)
	}

	bridge.httpServer = &http.Server{
		Addr:    bridge.config.ListenAddress,
		Handler: mux,
	}

	bridge.logger.Infof("Starting WebSSH Bridge server on %s", bridge.config.ListenAddress)

	// Start server with TLS
	if err := bridge.httpServer.ListenAndServeTLS(bridge.config.CertificateFile, bridge.config.KeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %v", err)
	}

	return nil
}

// Stop gracefully stops the WebSSH bridge server
func (bridge *WebSSHBridge) Stop() error {
	bridge.logger.Info("Shutting down WebSSH Bridge server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := bridge.httpServer.Shutdown(ctx); err != nil {
		bridge.logger.Errorf("HTTP server shutdown error: %v", err)
	}

	// Shutdown connection manager
	if err := bridge.connectionManager.Shutdown(); err != nil {
		bridge.logger.Errorf("Connection manager shutdown error: %v", err)
	}

	// Close rate limiter
	bridge.rateLimiter.Close()

	bridge.logger.Info("WebSSH Bridge server shutdown complete")
	return nil
}

// handleWebSocket handles WebSocket connections
func (bridge *WebSSHBridge) handleWebSocket(responseWriter http.ResponseWriter, request *http.Request) {
	// Parse target address
	targetAddress, err := bridge.connectionManager.ParseTargetAddress(request)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	// Get client IP
	clientIP := bridge.connectionManager.GetClientIP(request)

	// Check rate limiting
	if !bridge.rateLimiter.IsAllowed(clientIP) {
		http.Error(responseWriter, "Rate limit exceeded. Please wait before trying again", http.StatusTooManyRequests)
		bridge.logger.Warnf("Rate limit exceeded for IP %s connecting to %s", clientIP, targetAddress)
		return
	}

	// Upgrade HTTP connection to WebSocket
	webSocketConn, err := bridge.websocketUpgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		bridge.logger.Errorf("WebSocket upgrade error: %v", err)
		return
	}

	// Create bridge session
	session, err := bridge.connectionManager.CreateSession(webSocketConn, targetAddress, clientIP)
	if err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to create session", err)
		return
	}

	// Read SSH credentials from WebSocket
	credentials, err := bridge.readSSHCredentials(webSocketConn)
	if err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to read SSH credentials", err)
		if removeErr := bridge.connectionManager.RemoveSession(session.ID); removeErr != nil {
			bridge.logger.Errorf("Failed to remove session %s after credentials error: %v", session.ID, removeErr)
		}
		return
	}

	// Initialize session with SSH connection
	if err := bridge.connectionManager.InitializeSession(session, credentials); err != nil {
		bridge.handleWebSocketError(webSocketConn, "Failed to initialize SSH connection", err)
		return
	}

	bridge.logger.Infof("WebSocket session %s established: %s -> %s", session.ID, clientIP, targetAddress)

	// Wait for session completion
	if err := session.WaitForCompletion(); err != nil {
		bridge.logger.Debugf("SSH session %s completed with error: %v", session.ID, err)
	}

	// Clean up session
	if removeErr := bridge.connectionManager.RemoveSession(session.ID); removeErr != nil {
		bridge.logger.Errorf("Failed to remove session %s after completion: %v", session.ID, removeErr)
	}
}

// handleHealthCheck handles health check requests
func (bridge *WebSSHBridge) handleHealthCheck(responseWriter http.ResponseWriter, request *http.Request) {
	stats := bridge.connectionManager.GetStats()

	health := map[string]interface{}{
		"status":          "healthy",
		"timestamp":       time.Now().UTC(),
		"active_sessions": stats["active_sessions"],
		"total_sessions":  stats["total_sessions"],
		"uptime":          "unknown", // Could be implemented if needed
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(responseWriter).Encode(health); err != nil {
		bridge.logger.Errorf("Failed to encode health check response: %v", err)
		http.Error(responseWriter, "Internal server error", http.StatusInternalServerError)
	}
}

// handleMetrics handles metrics requests
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

// readSSHCredentials reads and parses SSH credentials from WebSocket
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

// handleWebSocketError handles WebSocket-related errors
func (bridge *WebSSHBridge) handleWebSocketError(webSocketConn *websocket.Conn, errorMessage string, err error) {
	if closeErr := webSocketConn.Close(); closeErr != nil {
		bridge.logger.Errorf("Failed to close WebSocket after error: %v", closeErr)
	}
	bridge.logger.Errorf("%s: %v", errorMessage, err)
}

// Run starts the server and handles graceful shutdown
func (bridge *WebSSHBridge) Run() error {
	// Setup signal handling for graceful shutdown
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	serverError := make(chan error, 1)
	go func() {
		serverError <- bridge.Start()
	}()

	// Wait for shutdown signal or server error
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
