package connection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"github.com/ubyte-source/ubyte-webssh-bridge/ssh"
)

// ConnectionManager manages all active WebSocket-SSH bridge connections
type ConnectionManager struct {
	// Configuration
	config *config.Configuration
	logger *logrus.Logger

	// Session management
	activeSessions map[string]*BridgeSession
	sessionsMutex  sync.RWMutex

	// Host connection tracking
	hostConnections map[string]int
	hostMutex       sync.RWMutex

	// Statistics
	totalSessions      int64
	successfulSessions int64
	failedSessions     int64
	statsMutex         sync.RWMutex
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(config *config.Configuration, logger *logrus.Logger) *ConnectionManager {
	manager := &ConnectionManager{
		config:          config,
		logger:          logger,
		activeSessions:  make(map[string]*BridgeSession),
		hostConnections: make(map[string]int),
	}

	// Start cleanup routine
	go manager.startCleanupRoutine()

	return manager
}

// CreateSession creates a new bridge session
func (manager *ConnectionManager) CreateSession(webSocketConn *websocket.Conn, targetAddress string, clientIP string) (*BridgeSession, error) {
	// Check global connection limit
	if err := manager.checkGlobalConnectionLimit(); err != nil {
		return nil, err
	}

	// Check per-host connection limit
	if err := manager.checkHostConnectionLimit(targetAddress); err != nil {
		return nil, err
	}

	// Generate unique session ID
	sessionID, err := manager.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	// Create new session
	session := NewBridgeSession(sessionID, webSocketConn, targetAddress, clientIP, manager.logger)

	// Configure WebSocket
	if err := manager.configureWebSocket(webSocketConn); err != nil {
		return nil, fmt.Errorf("failed to configure WebSocket: %v", err)
	}

	// Add to active sessions
	manager.sessionsMutex.Lock()
	manager.activeSessions[sessionID] = session
	manager.sessionsMutex.Unlock()

	// Update host connection count
	manager.hostMutex.Lock()
	manager.hostConnections[targetAddress]++
	manager.hostMutex.Unlock()

	// Update statistics
	manager.statsMutex.Lock()
	manager.totalSessions++
	manager.statsMutex.Unlock()

	if manager.logger != nil {
		manager.logger.Infof("Created new session %s for %s -> %s", sessionID, clientIP, targetAddress)
	}

	return session, nil
}

// InitializeSession initializes a session with SSH connection
func (manager *ConnectionManager) InitializeSession(session *BridgeSession, credentials message.Credentials) error {
	// Create SSH timeouts from configuration
	timeouts := ssh.NewSSHTimeouts(
		manager.config.SSHConnectTimeout,
		manager.config.SSHAuthTimeout,
		manager.config.SSHHandshakeTimeout,
	)

	// Initialize SSH connection
	if err := session.InitializeSSHConnection(credentials, timeouts); err != nil {
		manager.handleSessionFailure(session, err)
		return fmt.Errorf("failed to initialize SSH connection: %v", err)
	}

	// Start communication
	if err := session.StartCommunication(); err != nil {
		manager.handleSessionFailure(session, err)
		return fmt.Errorf("failed to start communication: %v", err)
	}

	// Update statistics
	manager.statsMutex.Lock()
	manager.successfulSessions++
	manager.statsMutex.Unlock()

	return nil
}

// RemoveSession removes a session from the manager
func (manager *ConnectionManager) RemoveSession(sessionID string) error {
	manager.sessionsMutex.Lock()
	session, exists := manager.activeSessions[sessionID]
	if exists {
		delete(manager.activeSessions, sessionID)
	}
	manager.sessionsMutex.Unlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Update host connection count
	manager.hostMutex.Lock()
	if count := manager.hostConnections[session.TargetAddress]; count > 0 {
		manager.hostConnections[session.TargetAddress]--
		if manager.hostConnections[session.TargetAddress] == 0 {
			delete(manager.hostConnections, session.TargetAddress)
		}
	}
	manager.hostMutex.Unlock()

	// Close the session
	if err := session.Close(); err != nil && manager.logger != nil {
		manager.logger.Errorf("Error closing session %s: %v", sessionID, err)
	}

	if manager.logger != nil {
		manager.logger.Infof("Removed session %s", sessionID)
	}

	return nil
}

// GetSession retrieves a session by ID
func (manager *ConnectionManager) GetSession(sessionID string) (*BridgeSession, bool) {
	manager.sessionsMutex.RLock()
	session, exists := manager.activeSessions[sessionID]
	manager.sessionsMutex.RUnlock()
	return session, exists
}

// GetActiveSessions returns a copy of all active sessions
func (manager *ConnectionManager) GetActiveSessions() map[string]*BridgeSession {
	manager.sessionsMutex.RLock()
	defer manager.sessionsMutex.RUnlock()

	sessions := make(map[string]*BridgeSession, len(manager.activeSessions))
	for id, session := range manager.activeSessions {
		sessions[id] = session
	}
	return sessions
}

// GetActiveSessionCount returns the number of active sessions
func (manager *ConnectionManager) GetActiveSessionCount() int {
	manager.sessionsMutex.RLock()
	defer manager.sessionsMutex.RUnlock()
	return len(manager.activeSessions)
}

// GetHostConnectionCount returns the number of connections to a specific host
func (manager *ConnectionManager) GetHostConnectionCount(targetAddress string) int {
	manager.hostMutex.RLock()
	defer manager.hostMutex.RUnlock()
	return manager.hostConnections[targetAddress]
}

// checkGlobalConnectionLimit checks if the global connection limit is exceeded
func (manager *ConnectionManager) checkGlobalConnectionLimit() error {
	if manager.GetActiveSessionCount() >= manager.config.MaxConnections {
		return fmt.Errorf("maximum number of connections (%d) reached", manager.config.MaxConnections)
	}
	return nil
}

// checkHostConnectionLimit checks if the per-host connection limit is exceeded
func (manager *ConnectionManager) checkHostConnectionLimit(targetAddress string) error {
	hostCount := manager.GetHostConnectionCount(targetAddress)
	if hostCount >= manager.config.MaxConnectionsPerHost {
		return fmt.Errorf("maximum number of connections to host %s (%d) reached", targetAddress, manager.config.MaxConnectionsPerHost)
	}
	return nil
}

// generateSessionID generates a unique session ID
func (manager *ConnectionManager) generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// configureWebSocket configures WebSocket connection settings
func (manager *ConnectionManager) configureWebSocket(webSocketConn *websocket.Conn) error {
	webSocketConn.SetReadLimit(manager.config.WebSocketReadLimit)

	// Set timeouts
	if err := webSocketConn.SetReadDeadline(time.Now().Add(manager.config.SSHHandshakeTimeout)); err != nil {
		return fmt.Errorf("failed to set WebSocket read deadline: %v", err)
	}
	if err := webSocketConn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("failed to set WebSocket write deadline: %v", err)
	}

	// Set ping handler
	webSocketConn.SetPingHandler(func(appData string) error {
		if manager.logger != nil {
			manager.logger.Debug("Received WebSocket ping, sending pong")
		}
		return webSocketConn.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})

	return nil
}

// handleSessionFailure handles session initialization failures
func (manager *ConnectionManager) handleSessionFailure(session *BridgeSession, err error) {
	manager.statsMutex.Lock()
	manager.failedSessions++
	manager.statsMutex.Unlock()

	if manager.logger != nil {
		manager.logger.Errorf("Session %s failed: %v", session.ID, err)
	}

	// Remove from active sessions
	if removeErr := manager.RemoveSession(session.ID); removeErr != nil && manager.logger != nil {
		manager.logger.Errorf("Failed to remove failed session %s: %v", session.ID, removeErr)
	}
}

// startCleanupRoutine starts a routine to clean up inactive sessions
func (manager *ConnectionManager) startCleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		manager.cleanupInactiveSessions()
	}
}

// cleanupInactiveSessions removes sessions that have been inactive for too long
func (manager *ConnectionManager) cleanupInactiveSessions() {
	cutoff := time.Now().Add(-manager.config.ConnectionTimeout)
	var sessionsToRemove []string

	manager.sessionsMutex.RLock()
	for id, session := range manager.activeSessions {
		if session.LastActivity.Before(cutoff) && !session.IsActive {
			sessionsToRemove = append(sessionsToRemove, id)
		}
	}
	manager.sessionsMutex.RUnlock()

	for _, sessionID := range sessionsToRemove {
		if manager.logger != nil {
			manager.logger.Infof("Cleaning up inactive session %s", sessionID)
		}
		if err := manager.RemoveSession(sessionID); err != nil && manager.logger != nil {
			manager.logger.Errorf("Failed to remove inactive session %s: %v", sessionID, err)
		}
	}
}

// ParseTargetAddress extracts the target SSH address from HTTP request URL path
// The expected format is: /ws/{host}/{port}
func (manager *ConnectionManager) ParseTargetAddress(request *http.Request) (string, error) {
	pathParts := strings.Split(request.URL.Path, "/")
	if len(pathParts) < 4 {
		return "", fmt.Errorf("URL does not contain valid host and port")
	}
	return pathParts[2] + ":" + pathParts[3], nil
}

// GetClientIP extracts the client IP address from the HTTP request
func (manager *ConnectionManager) GetClientIP(request *http.Request) string {
	// Check for X-Forwarded-For header first
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if multiple are present
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check for X-Real-IP header
	if xri := request.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		return host
	}

	return request.RemoteAddr
}

// GetStats returns connection manager statistics
func (manager *ConnectionManager) GetStats() map[string]interface{} {
	manager.statsMutex.RLock()
	totalSessions := manager.totalSessions
	successfulSessions := manager.successfulSessions
	failedSessions := manager.failedSessions
	manager.statsMutex.RUnlock()

	activeSessionCount := manager.GetActiveSessionCount()

	manager.hostMutex.RLock()
	hostStats := make(map[string]int)
	for host, count := range manager.hostConnections {
		hostStats[host] = count
	}
	manager.hostMutex.RUnlock()

	return map[string]interface{}{
		"active_sessions":     activeSessionCount,
		"total_sessions":      totalSessions,
		"successful_sessions": successfulSessions,
		"failed_sessions":     failedSessions,
		"host_connections":    hostStats,
		"max_connections":     manager.config.MaxConnections,
		"max_per_host":        manager.config.MaxConnectionsPerHost,
	}
}

// Shutdown gracefully shuts down the connection manager
func (manager *ConnectionManager) Shutdown() error {
	if manager.logger != nil {
		manager.logger.Info("Shutting down connection manager...")
	}

	// Get all active sessions
	sessions := manager.GetActiveSessions()

	// Close all active sessions
	for sessionID := range sessions {
		if err := manager.RemoveSession(sessionID); err != nil && manager.logger != nil {
			manager.logger.Errorf("Error closing session %s during shutdown: %v", sessionID, err)
		}
	}

	if manager.logger != nil {
		manager.logger.Infof("Connection manager shutdown complete. Closed %d sessions.", len(sessions))
	}

	return nil
}
