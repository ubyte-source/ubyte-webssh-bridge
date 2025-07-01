package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"github.com/ubyte-source/ubyte-webssh-bridge/ssh"
)

// ManagerOperation represents operations that can be performed on the manager.
type ManagerOperation struct {
	Type     ManagerOpType
	Data     interface{}
	Response chan ManagerResponse
}

// ManagerOpType defines the type of manager operation.
type ManagerOpType int

const (
	OpAddSession ManagerOpType = iota
	OpRemoveSession
	OpGetSession
	OpGetStats
	OpGetActiveSessions
	OpUpdateStats
	OpCheckLimits
	OpCleanupInactiveSessions
	OpShutdown
)

// ManagerResponse represents the response from a manager operation.
type ManagerResponse struct {
	Success bool
	Data    interface{}
	Error   error
}

// ConnectionManager handles the lifecycle of all WebSocket-SSH sessions,
// including creation, tracking, and cleanup. It enforces connection limits
// and collects statistics using a channel-based coordination system.
type ConnectionManager struct {
	config *config.Configuration
	logger *logrus.Logger

	// Channel-based coordination system for thread-safe operations
	operationChan chan ManagerOperation
	shutdownChan  chan struct{}

	// Memory pools for allocation optimization
	globalBufferPool *BufferPool
	sessionPool      sync.Pool

	// Internal state managed by the coordinator goroutine
	activeSessions     map[string]*BridgeSession
	hostConnections    map[string]int
	totalSessions      int64
	successfulSessions int64
	failedSessions     int64
}

// NewConnectionManager creates and returns a new ConnectionManager instance
// with channel-based coordination and memory pool optimization.
func NewConnectionManager(config *config.Configuration, logger *logrus.Logger) *ConnectionManager {
	manager := &ConnectionManager{
		config:           config,
		logger:           logger,
		operationChan:    make(chan ManagerOperation, 100),
		shutdownChan:     make(chan struct{}),
		globalBufferPool: NewBufferPool(),
		sessionPool: sync.Pool{
			New: func() interface{} {
				return &BridgeSession{}
			},
		},
		activeSessions:  make(map[string]*BridgeSession),
		hostConnections: make(map[string]int),
	}

	go manager.coordinatorLoop()
	go manager.startCleanupRoutine()

	return manager
}

// coordinatorLoop handles all manager operations through a single goroutine
// to ensure thread-safe state management without mutex contention.
func (manager *ConnectionManager) coordinatorLoop() {
	for {
		select {
		case op := <-manager.operationChan:
			manager.handleOperation(op)
		case <-manager.shutdownChan:
			return
		}
	}
}

// handleOperation processes a manager operation and sends the response.
func (manager *ConnectionManager) handleOperation(op ManagerOperation) {
	var response ManagerResponse

	switch op.Type {
	case OpAddSession:
		data := op.Data.(map[string]interface{})
		sessionID := data["sessionID"].(string)
		session := data["session"].(*BridgeSession)
		targetAddress := data["targetAddress"].(string)

		manager.activeSessions[sessionID] = session
		manager.hostConnections[targetAddress]++
		manager.totalSessions++

		response = ManagerResponse{Success: true}

	case OpRemoveSession:
		sessionID := op.Data.(string)
		session, exists := manager.activeSessions[sessionID]

		if !exists {
			response = ManagerResponse{Success: false, Error: fmt.Errorf("session %s not found", sessionID)}
			break
		}

		delete(manager.activeSessions, sessionID)
		if count, ok := manager.hostConnections[session.TargetAddress]; ok && count > 0 {
			manager.hostConnections[session.TargetAddress]--
			if manager.hostConnections[session.TargetAddress] == 0 {
				delete(manager.hostConnections, session.TargetAddress)
			}
		}
		response = ManagerResponse{Success: true, Data: session}

	case OpGetSession:
		sessionID := op.Data.(string)
		session, exists := manager.activeSessions[sessionID]
		response = ManagerResponse{Success: exists, Data: session}

	case OpGetActiveSessions:
		sessionCopy := make(map[string]*BridgeSession, len(manager.activeSessions))
		for id, session := range manager.activeSessions {
			sessionCopy[id] = session
		}
		response = ManagerResponse{Success: true, Data: sessionCopy}

	case OpGetStats:
		// Create snapshot of current stats
		hostStats := make(map[string]int)
		for host, count := range manager.hostConnections {
			hostStats[host] = count
		}

		stats := map[string]interface{}{
			"active_sessions":     len(manager.activeSessions),
			"total_sessions":      manager.totalSessions,
			"successful_sessions": manager.successfulSessions,
			"failed_sessions":     manager.failedSessions,
			"host_connections":    hostStats,
			"max_connections":     manager.config.MaxConnections,
			"max_per_host":        manager.config.MaxConnectionsPerHost,
		}
		response = ManagerResponse{Success: true, Data: stats}

	case OpUpdateStats:
		data := op.Data.(map[string]interface{})
		if increment, ok := data["successful"]; ok && increment.(bool) {
			manager.successfulSessions++
		}
		if increment, ok := data["failed"]; ok && increment.(bool) {
			manager.failedSessions++
		}
		response = ManagerResponse{Success: true}

	case OpCheckLimits:
		data := op.Data.(map[string]interface{})
		targetAddress := data["targetAddress"].(string)

		if err := manager.checkGlobalConnectionLimit(); err != nil {
			response = ManagerResponse{Success: false, Error: err}
			break
		}
		if err := manager.checkHostConnectionLimit(targetAddress); err != nil {
			response = ManagerResponse{Success: false, Error: err}
			break
		}
		response = ManagerResponse{Success: true}

	case OpCleanupInactiveSessions:
		manager.cleanupInactiveSessions()
		response = ManagerResponse{Success: true}
	}

	// Send response back
	select {
	case op.Response <- response:
	case <-time.After(5 * time.Second):
		manager.logger.Errorf("Failed to send manager operation response - timeout")
	}
}

// executeOperation sends an operation to the coordinator and waits for response.
func (manager *ConnectionManager) executeOperation(opType ManagerOpType, data interface{}) ManagerResponse {
	responseChan := make(chan ManagerResponse, 1)
	op := ManagerOperation{
		Type:     opType,
		Data:     data,
		Response: responseChan,
	}

	select {
	case manager.operationChan <- op:
		select {
		case response := <-responseChan:
			return response
		case <-time.After(10 * time.Second):
			return ManagerResponse{Success: false, Error: fmt.Errorf("operation timeout")}
		}
	case <-time.After(5 * time.Second):
		return ManagerResponse{Success: false, Error: fmt.Errorf("operation channel blocked")}
	}
}

// CreateSession establishes a new bridge session after validating connection limits.
func (manager *ConnectionManager) CreateSession(webSocketConn *websocket.Conn, targetAddress, clientIP string) (*BridgeSession, error) {
	response := manager.executeOperation(OpCheckLimits, map[string]interface{}{
		"targetAddress": targetAddress,
	})
	if !response.Success {
		return nil, response.Error
	}

	sessionID, err := manager.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	session := manager.sessionPool.Get().(*BridgeSession)
	session.ID = sessionID
	session.WebSocketConn = webSocketConn
	session.TargetAddress = targetAddress
	session.ClientIP = clientIP
	session.Logger = manager.logger
	session.CreatedAt = time.Now()
	session.stateMachine = NewSessionStateMachine()
	session.Context, session.CancelFunc = context.WithCancel(context.Background())
	session.WaitGroup = &sync.WaitGroup{}
	session.wsWriteChan = make(chan *WSMessage, 100)
	session.controlChan = make(chan *ControlSignal, 10)
	session.shutdownChan = make(chan struct{})
	session.bufferPool = NewBufferPool()
	session.messagePool = NewMessagePool()
	session.MessageProcessor = message.NewMessageProcessor(manager.logger)
	session.WaitGroup.Add(2)
	go session.wsWriterLoop()
	go session.controlHandler()

	if err := manager.configureWebSocket(webSocketConn); err != nil {
		return nil, fmt.Errorf("failed to configure WebSocket: %v", err)
	}

	response = manager.executeOperation(OpAddSession, map[string]interface{}{
		"sessionID":     sessionID,
		"session":       session,
		"targetAddress": targetAddress,
	})
	if !response.Success {
		return nil, response.Error
	}

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

	manager.executeOperation(OpUpdateStats, map[string]interface{}{
		"successful": true,
	})

	return nil
}

// RemoveSession terminates a session and removes it from the active pool.
func (manager *ConnectionManager) RemoveSession(sessionID string) error {
	response := manager.executeOperation(OpRemoveSession, sessionID)
	if !response.Success {
		return response.Error
	}

	session := response.Data.(*BridgeSession)
	if err := session.Close(); err != nil {
		manager.logger.Errorf("Error closing session %s: %v", sessionID, err)
	}
	manager.sessionPool.Put(session)

	manager.logger.Infof("Removed session %s", sessionID)
	return nil
}

// GetSession retrieves a session by its ID.
func (manager *ConnectionManager) GetSession(sessionID string) (*BridgeSession, bool) {
	response := manager.executeOperation(OpGetSession, sessionID)
	if response.Success && response.Data != nil {
		return response.Data.(*BridgeSession), true
	}
	return nil, false
}

// GetActiveSessions returns a copy of the map of active sessions.
func (manager *ConnectionManager) GetActiveSessions() map[string]*BridgeSession {
	response := manager.executeOperation(OpGetActiveSessions, nil)
	if !response.Success {
		return make(map[string]*BridgeSession)
	}
	return response.Data.(map[string]*BridgeSession)
}

// GetActiveSessionCount returns the current number of active sessions.
func (manager *ConnectionManager) GetActiveSessionCount() int {
	response := manager.executeOperation(OpGetStats, nil)
	if response.Success {
		stats := response.Data.(map[string]interface{})
		return stats["active_sessions"].(int)
	}
	return 0
}

// GetHostConnectionCount returns the number of active connections to a specific host.
func (manager *ConnectionManager) GetHostConnectionCount(targetAddress string) int {
	response := manager.executeOperation(OpGetStats, nil)
	if response.Success {
		stats := response.Data.(map[string]interface{})
		hostStats := stats["host_connections"].(map[string]int)
		return hostStats[targetAddress]
	}
	return 0
}

// checkGlobalConnectionLimit verifies that the total number of active sessions
// is within the configured limit. Used internally by the coordinator.
func (manager *ConnectionManager) checkGlobalConnectionLimit() error {
	if len(manager.activeSessions) >= manager.config.MaxConnections {
		return fmt.Errorf("maximum number of connections (%d) reached", manager.config.MaxConnections)
	}
	return nil
}

// checkHostConnectionLimit verifies that the number of active sessions to a
// specific host is within the configured limit. Used internally by the coordinator.
func (manager *ConnectionManager) checkHostConnectionLimit(targetAddress string) error {
	hostCount := manager.hostConnections[targetAddress]
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
	manager.executeOperation(OpUpdateStats, map[string]interface{}{
		"failed": true,
	})
	manager.logger.Errorf("Session %s failed: %v", session.ID, err)
	if removeErr := manager.RemoveSession(session.ID); removeErr != nil {
		manager.logger.Errorf("Failed to remove failed session %s: %v", session.ID, removeErr)
	}
}

// startCleanupRoutine runs a periodic task to remove inactive sessions.
func (manager *ConnectionManager) startCleanupRoutine() {
	ticker := time.NewTicker(manager.config.SessionIdleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			manager.executeOperation(OpCleanupInactiveSessions, nil)
		case <-manager.shutdownChan:
			return
		}
	}
}

// cleanupInactiveSessions iterates through active sessions and removes those
// that have been idle for longer than the configured timeout.
func (manager *ConnectionManager) cleanupInactiveSessions() {
	idleThreshold := time.Now().Add(-manager.config.SessionIdleTimeout)
	sessionsToRemove := make([]string, 0)

	for id, session := range manager.activeSessions {
		if session.GetLastActivity().Before(idleThreshold) {
			sessionsToRemove = append(sessionsToRemove, id)
		}
	}

	for _, id := range sessionsToRemove {
		manager.logger.Infof("Session %s has been idle for too long, removing.", id)
		manager.handleOperation(ManagerOperation{
			Type: OpRemoveSession,
			Data: id,
			// No response needed for internal cleanup
			Response: make(chan ManagerResponse, 1),
		})
	}
}

// ParseTargetAddress extracts the target SSH host and port from the request URL.
// The expected URL format is /ws/{host}/{port}.
var targetAddressRegex = regexp.MustCompile(`^/ws/([^/]+)/(\d+)$`)

func (manager *ConnectionManager) ParseTargetAddress(request *http.Request) (string, error) {
	matches := targetAddressRegex.FindStringSubmatch(request.URL.Path)
	if len(matches) != 3 {
		return "", fmt.Errorf("URL path does not match expected format /ws/{host}/{port}")
	}
	return net.JoinHostPort(matches[1], matches[2]), nil
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
	response := manager.executeOperation(OpGetStats, nil)
	if response.Success {
		return response.Data.(map[string]interface{})
	}

	return map[string]interface{}{
		"active_sessions":     0,
		"total_sessions":      0,
		"successful_sessions": 0,
		"failed_sessions":     0,
		"host_connections":    make(map[string]int),
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
