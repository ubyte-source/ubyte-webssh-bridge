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

// ConnectionManager handles the lifecycle of all WebSocket-SSH sessions,
// including creation, tracking, and cleanup. It enforces connection limits
// and collects statistics.
type ConnectionManager struct {
	config *config.Configuration
	logger *logrus.Logger

	activeSessions map[string]*BridgeSession
	sessionsMutex  sync.RWMutex

	hostConnections map[string]int
	hostMutex       sync.RWMutex

	totalSessions      int64
	successfulSessions int64
	failedSessions     int64
	statsMutex         sync.RWMutex
}

// NewConnectionManager creates and returns a new ConnectionManager instance.
// It initializes the session and host tracking maps and starts a background
// routine to clean up inactive sessions.
func NewConnectionManager(config *config.Configuration, logger *logrus.Logger) *ConnectionManager {
	manager := &ConnectionManager{
		config:          config,
		logger:          logger,
		activeSessions:  make(map[string]*BridgeSession),
		hostConnections: make(map[string]int),
	}
	go manager.startCleanupRoutine()
	return manager
}

// CreateSession establishes a new bridge session after validating connection limits.
// It generates a unique ID for the session, configures the WebSocket connection,
// and adds the session to the active pool.
func (manager *ConnectionManager) CreateSession(webSocketConn *websocket.Conn, targetAddress, clientIP string) (*BridgeSession, error) {
	if err := manager.checkGlobalConnectionLimit(); err != nil {
		return nil, err
	}
	if err := manager.checkHostConnectionLimit(targetAddress); err != nil {
		return nil, err
	}

	sessionID, err := manager.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	session := NewBridgeSession(sessionID, webSocketConn, targetAddress, clientIP, manager.logger)
	if err := manager.configureWebSocket(webSocketConn); err != nil {
		return nil, fmt.Errorf("failed to configure WebSocket: %v", err)
	}

	manager.sessionsMutex.Lock()
	manager.activeSessions[sessionID] = session
	manager.sessionsMutex.Unlock()

	manager.hostMutex.Lock()
	manager.hostConnections[targetAddress]++
	manager.hostMutex.Unlock()

	manager.statsMutex.Lock()
	manager.totalSessions++
	manager.statsMutex.Unlock()

	manager.logger.Infof("Created new session %s for %s -> %s", sessionID, clientIP, targetAddress)
	return session, nil
}

// InitializeSession completes the session setup by establishing the SSH connection
// and starting the bidirectional communication bridge.
func (manager *ConnectionManager) InitializeSession(session *BridgeSession, credentials message.Credentials) error {
	timeouts := ssh.NewSSHTimeouts(
		manager.config.SSHConnectTimeout,
		manager.config.SSHAuthTimeout,
		manager.config.SSHHandshakeTimeout,
	)

	if err := session.InitializeSSHConnection(credentials, timeouts); err != nil {
		manager.handleSessionFailure(session, err)
		return fmt.Errorf("failed to initialize SSH connection: %v", err)
	}

	if err := session.StartCommunication(); err != nil {
		manager.handleSessionFailure(session, err)
		return fmt.Errorf("failed to start communication: %v", err)
	}

	manager.statsMutex.Lock()
	manager.successfulSessions++
	manager.statsMutex.Unlock()

	return nil
}

// RemoveSession terminates a session and removes it from the active pool.
// It updates connection counts and ensures all resources are released.
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

	manager.hostMutex.Lock()
	if count, ok := manager.hostConnections[session.TargetAddress]; ok && count > 0 {
		manager.hostConnections[session.TargetAddress]--
		if manager.hostConnections[session.TargetAddress] == 0 {
			delete(manager.hostConnections, session.TargetAddress)
		}
	}
	manager.hostMutex.Unlock()

	if err := session.Close(); err != nil {
		manager.logger.Errorf("Error closing session %s: %v", sessionID, err)
	}

	manager.logger.Infof("Removed session %s", sessionID)
	return nil
}

// GetSession retrieves a session by its ID.
func (manager *ConnectionManager) GetSession(sessionID string) (*BridgeSession, bool) {
	manager.sessionsMutex.RLock()
	defer manager.sessionsMutex.RUnlock()
	session, exists := manager.activeSessions[sessionID]
	return session, exists
}

// GetActiveSessions returns a copy of the map of active sessions.
func (manager *ConnectionManager) GetActiveSessions() map[string]*BridgeSession {
	manager.sessionsMutex.RLock()
	defer manager.sessionsMutex.RUnlock()
	sessions := make(map[string]*BridgeSession, len(manager.activeSessions))
	for id, session := range manager.activeSessions {
		sessions[id] = session
	}
	return sessions
}

// GetActiveSessionCount returns the current number of active sessions.
func (manager *ConnectionManager) GetActiveSessionCount() int {
	manager.sessionsMutex.RLock()
	defer manager.sessionsMutex.RUnlock()
	return len(manager.activeSessions)
}

// GetHostConnectionCount returns the number of active connections to a specific host.
func (manager *ConnectionManager) GetHostConnectionCount(targetAddress string) int {
	manager.hostMutex.RLock()
	defer manager.hostMutex.RUnlock()
	return manager.hostConnections[targetAddress]
}

// checkGlobalConnectionLimit verifies that the total number of active sessions
// is within the configured limit.
func (manager *ConnectionManager) checkGlobalConnectionLimit() error {
	if manager.GetActiveSessionCount() >= manager.config.MaxConnections {
		return fmt.Errorf("maximum number of connections (%d) reached", manager.config.MaxConnections)
	}
	return nil
}

// checkHostConnectionLimit verifies that the number of active sessions to a
// specific host is within the configured limit.
func (manager *ConnectionManager) checkHostConnectionLimit(targetAddress string) error {
	hostCount := manager.GetHostConnectionCount(targetAddress)
	if hostCount >= manager.config.MaxConnectionsPerHost {
		return fmt.Errorf("maximum number of connections to host %s (%d) reached", targetAddress, manager.config.MaxConnectionsPerHost)
	}
	return nil
}

// generateSessionID creates a cryptographically secure, unique identifier for a session.
func (manager *ConnectionManager) generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// configureWebSocket applies the necessary settings to the WebSocket connection,
// including read limits and ping/pong handlers.
func (manager *ConnectionManager) configureWebSocket(webSocketConn *websocket.Conn) error {
	webSocketConn.SetReadLimit(manager.config.WebSocketReadLimit)

	// Set ping handler to respond to client pings
	webSocketConn.SetPingHandler(func(appData string) error {
		manager.logger.Debug("Received WebSocket ping, sending pong")
		return webSocketConn.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})

	// Set pong handler to log received pongs
	webSocketConn.SetPongHandler(func(appData string) error {
		manager.logger.Debug("Received WebSocket pong")
		return nil
	})

	return nil
}

// handleSessionFailure logs the failure and ensures the session is removed.
func (manager *ConnectionManager) handleSessionFailure(session *BridgeSession, err error) {
	manager.statsMutex.Lock()
	manager.failedSessions++
	manager.statsMutex.Unlock()
	manager.logger.Errorf("Session %s failed: %v", session.ID, err)
	if removeErr := manager.RemoveSession(session.ID); removeErr != nil {
		manager.logger.Errorf("Failed to remove failed session %s: %v", session.ID, removeErr)
	}
}

// startCleanupRoutine runs a periodic task to remove inactive sessions.
func (manager *ConnectionManager) startCleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		manager.cleanupInactiveSessions()
	}
}

// cleanupInactiveSessions iterates through active sessions and removes any
// that have been idle for longer than the configured timeout.
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
		manager.logger.Infof("Cleaning up inactive session %s", sessionID)
		if err := manager.RemoveSession(sessionID); err != nil {
			manager.logger.Errorf("Failed to remove inactive session %s: %v", sessionID, err)
		}
	}
}

// ParseTargetAddress extracts the target SSH host and port from the request URL.
// The expected URL format is /ws/{host}/{port}.
func (manager *ConnectionManager) ParseTargetAddress(request *http.Request) (string, error) {
	pathParts := strings.Split(request.URL.Path, "/")
	if len(pathParts) < 4 {
		return "", fmt.Errorf("URL does not contain a valid host and port")
	}
	return net.JoinHostPort(pathParts[2], pathParts[3]), nil
}

// GetClientIP determines the client's IP address by checking common proxy headers
// first, then falling back to the remote address of the connection.
func (manager *ConnectionManager) GetClientIP(request *http.Request) string {
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := request.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		return host
	}
	return request.RemoteAddr
}

// GetStats returns a map of the connection manager's current statistics.
func (manager *ConnectionManager) GetStats() map[string]interface{} {
	manager.statsMutex.RLock()
	total := manager.totalSessions
	successful := manager.successfulSessions
	failed := manager.failedSessions
	manager.statsMutex.RUnlock()

	active := manager.GetActiveSessionCount()

	manager.hostMutex.RLock()
	hostStats := make(map[string]int)
	for host, count := range manager.hostConnections {
		hostStats[host] = count
	}
	manager.hostMutex.RUnlock()

	return map[string]interface{}{
		"active_sessions":     active,
		"total_sessions":      total,
		"successful_sessions": successful,
		"failed_sessions":     failed,
		"host_connections":    hostStats,
		"max_connections":     manager.config.MaxConnections,
		"max_per_host":        manager.config.MaxConnectionsPerHost,
	}
}

// Shutdown gracefully terminates all active sessions and shuts down the manager.
func (manager *ConnectionManager) Shutdown() error {
	manager.logger.Info("Shutting down connection manager...")
	sessions := manager.GetActiveSessions()
	for sessionID := range sessions {
		if err := manager.RemoveSession(sessionID); err != nil {
			manager.logger.Errorf("Error closing session %s during shutdown: %v", sessionID, err)
		}
	}
	manager.logger.Infof("Connection manager shutdown complete. Closed %d sessions.", len(sessions))
	return nil
}
