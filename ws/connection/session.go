package connection

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"github.com/ubyte-source/ubyte-webssh-bridge/ssh"
)

// Error patterns for connection close error handling
const (
	ErrClosedNetworkConnection = "use of closed network connection"
	ErrBrokenPipe              = "broken pipe"
	ErrConnectionReset         = "connection reset by peer"
	ErrWebSocketCloseSent      = "websocket: close sent"
	ErrEOF                     = "EOF"
)

// Error patterns for fatal error classification
const (
	ErrUnmarshalError            = "error unmarshalling"
	ErrInvalidTerminalDimensions = "invalid terminal dimensions"
	ErrCannotResizeTerminal      = "cannot resize terminal"
)

// BridgeSession represents a single, managed WebSocket-to-SSH connection
// using channel-based communication for thread-safe operations.
type BridgeSession struct {
	ID            string
	TargetAddress string
	ClientIP      string

	WebSocketConn *websocket.Conn
	SSHClient     *ssh.SSHClient
	SSHSession    *ssh.SSHSession

	MessageProcessor *message.MessageProcessor

	Context    context.Context
	CancelFunc context.CancelFunc
	WaitGroup  *sync.WaitGroup

	// Channel-based communication system
	stateMachine *SessionStateMachine
	wsWriteChan  chan *WSMessage     // Channel for WebSocket writes
	controlChan  chan *ControlSignal // Channel for control operations
	shutdownChan chan struct{}       // Channel for shutdown signaling

	// Memory pools for allocation optimization
	bufferPool  *BufferPool
	messagePool *MessagePool

	CreatedAt    time.Time
	lastActivity int64 // Unix timestamp for atomic updates

	Logger *logrus.Logger
}

// NewBridgeSession creates and initializes a new BridgeSession
// with channel-based communication and memory pool optimization.
func NewBridgeSession(id string, webSocketConn *websocket.Conn, targetAddress, clientIP string, logger *logrus.Logger) *BridgeSession {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()

	session := &BridgeSession{
		ID:               id,
		TargetAddress:    targetAddress,
		ClientIP:         clientIP,
		WebSocketConn:    webSocketConn,
		MessageProcessor: message.NewMessageProcessor(logger),
		Context:          ctx,
		CancelFunc:       cancel,
		WaitGroup:        &sync.WaitGroup{},
		stateMachine:     NewSessionStateMachine(),

		wsWriteChan:  make(chan *WSMessage, 100),
		controlChan:  make(chan *ControlSignal, 10),
		shutdownChan: make(chan struct{}),

		bufferPool:  NewBufferPool(),
		messagePool: NewMessagePool(),

		CreatedAt: now,
		Logger:    logger,
	}
	atomic.StoreInt64(&session.lastActivity, now.Unix())

	session.WaitGroup.Add(2)
	go session.wsWriterLoop()
	go session.controlHandler()

	return session
}

// InitializeSSHConnection establishes the underlying SSH connection for the session.
func (s *BridgeSession) InitializeSSHConnection(credentials message.Credentials, timeouts ssh.SSHTimeouts) error {
	s.SSHClient = ssh.NewSSHClient(credentials, s.TargetAddress, timeouts, s.Logger)

	if err := s.SSHClient.Connect(s.Context, timeouts); err != nil {
		return fmt.Errorf("failed to connect SSH client: %v", err)
	}

	sshSession, err := s.SSHClient.NewSession()
	if err != nil {
		if closeErr := s.SSHClient.Close(); closeErr != nil {
			s.Logger.Errorf("Failed to close SSH client after session creation error: %v", closeErr)
		}
		return fmt.Errorf("failed to create SSH session: %v", err)
	}

	s.SSHSession = sshSession
	return nil
}

// StartCommunication launches the goroutines that bridge communication between
// the WebSocket and SSH connections.
func (s *BridgeSession) StartCommunication() error {
	if s.SSHSession == nil {
		return fmt.Errorf("SSH session not initialized")
	}

	// Transition to connecting state
	if !s.stateMachine.TransitionTo(StateConnecting) {
		return fmt.Errorf("invalid state transition to connecting")
	}

	s.WaitGroup.Add(3)
	go s.handleWebSocketMessages()
	go s.handleSSHOutput()
	go s.sendKeepAlive()

	if err := s.SSHSession.StartShell(); err != nil {
		s.Logger.Errorf("Error starting SSH shell: %v", err)
		return fmt.Errorf("failed to start SSH shell: %v", err)
	}

	// Transition to active state
	if !s.stateMachine.TransitionTo(StateActive) {
		return fmt.Errorf("invalid state transition to active")
	}

	s.updateLastActivity()
	s.Logger.Infof("Bridge session %s started successfully", s.ID)
	return nil
}

// handleWebSocketMessages reads messages from the WebSocket and forwards them
// to the appropriate handler.
func (s *BridgeSession) handleWebSocketMessages() {
	defer s.WaitGroup.Done()
	defer func() {
		if stdinPipe := s.SSHSession.GetStdinPipe(); stdinPipe != nil {
			if err := stdinPipe.Close(); err != nil {
				s.Logger.Errorf("Failed to close stdin pipe: %v", err)
			}
		}
	}()

	for {
		select {
		case <-s.Context.Done():
			return
		default:
		}

		messageType, reader, err := s.readNextWebSocketFrame()
		if err != nil {
			if !s.isAcceptableCloseError(err) {
				s.Logger.Errorf("WebSocket frame error: %v", err)
			} else {
				s.Logger.Debugf("WebSocket closed normally: %v", err)
			}
			return
		}

		s.updateLastActivity()

		if err := s.processWebSocketMessage(messageType, reader); err != nil {
			// Check if this is a fatal error that should close the connection
			if s.isFatalError(err) {
				s.Logger.Errorf("Fatal message processing error: %v", err)
				return
			}
			// For non-fatal errors, just log and continue
			s.Logger.Warnf("Non-fatal message processing error: %v", err)
		}
	}
}

// readNextWebSocketFrame safely reads the next message from the WebSocket,
// respecting the session's context for cancellation.
func (s *BridgeSession) readNextWebSocketFrame() (int, io.Reader, error) {
	type result struct {
		messageType int
		reader      io.Reader
		err         error
	}
	resultChan := make(chan result, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		msgType, r, err := s.WebSocketConn.NextReader()
		select {
		case resultChan <- result{msgType, r, err}:
		case <-s.Context.Done():
			// Context was cancelled, just exit the goroutine
			// The main Close() method will handle connection cleanup
		}
	}()

	select {
	case res := <-resultChan:
		<-done
		return res.messageType, res.reader, res.err
	case <-s.Context.Done():
		<-done
		return 0, nil, s.Context.Err()
	}
}

// processWebSocketMessage dispatches a WebSocket message to the correct processor
// based on its type (binary or text).
func (s *BridgeSession) processWebSocketMessage(messageType int, reader io.Reader) error {
	stdin := s.SSHSession.GetStdinPipe()
	session := s.SSHSession.GetSession()

	switch messageType {
	case websocket.BinaryMessage:
		return s.MessageProcessor.ProcessBinaryMessage(reader, stdin)
	case websocket.TextMessage:
		return s.MessageProcessor.ProcessTextMessage(reader, stdin, session)
	default:
		return nil // Ignore other message types
	}
}

// handleSSHOutput reads data from the SSH session's stdout and forwards it
// to the WebSocket client.
func (s *BridgeSession) handleSSHOutput() {
	defer s.WaitGroup.Done()

	stdout := s.SSHSession.GetStdoutPipe()
	buffer := make([]byte, 8192)

	for {
		select {
		case <-s.Context.Done():
			return
		default:
		}

		n, err := stdout.Read(buffer)
		if n > 0 {
			if writeErr := s.safeWriteWebSocketMessage(websocket.BinaryMessage, buffer[:n]); writeErr != nil {
				if !s.isAcceptableCloseError(writeErr) {
					s.Logger.Errorf("Error writing SSH output to WebSocket: %v", writeErr)
				} else {
					s.Logger.Debugf("WebSocket write failed due to connection close: %v", writeErr)
				}
				return
			}
			s.updateLastActivity()
		}

		if err != nil {
			if err != io.EOF {
				s.Logger.Errorf("Error reading SSH stdout: %v", err)
			} else {
				s.Logger.Debugf("SSH stdout closed normally (EOF)")
			}
			return
		}
	}
}

// sendKeepAlive sends periodic ping messages to the client to keep the
// WebSocket connection alive.
func (s *BridgeSession) sendKeepAlive() {
	defer s.WaitGroup.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.Context.Done():
			return
		case <-ticker.C:
			if err := s.safeWriteWebSocketMessage(websocket.PingMessage, nil); err != nil {
				if !s.isAcceptableCloseError(err) {
					s.Logger.Errorf("Error sending ping: %v", err)
				} else {
					s.Logger.Debugf("Ping failed due to connection close: %v", err)
				}
				return
			}
		}
	}
}

// safeWriteWebSocketMessage provides a thread-safe way to write messages
// to the WebSocket connection using channel-based communication.
func (s *BridgeSession) safeWriteWebSocketMessage(messageType int, data []byte) error {
	if s.stateMachine.IsClosed() {
		return fmt.Errorf("connection is closed")
	}

	dataCopy := s.bufferPool.GetCopy(data)
	msg := s.messagePool.GetWSMessage(messageType, dataCopy)

	select {
	case s.wsWriteChan <- msg:
		return nil
	case <-time.After(5 * time.Second):
		s.bufferPool.Put(dataCopy)
		s.messagePool.PutWSMessage(msg)
		return fmt.Errorf("WebSocket write channel blocked")
	case <-s.Context.Done():
		s.bufferPool.Put(dataCopy)
		s.messagePool.PutWSMessage(msg)
		return fmt.Errorf("session closed")
	}
}

// safeCloseWebSocket provides a thread-safe way to close the WebSocket connection.
func (s *BridgeSession) safeCloseWebSocket() error {
	if s.WebSocketConn == nil {
		return nil
	}

	closeErr := s.WebSocketConn.Close()
	if closeErr != nil && s.isAcceptableCloseError(closeErr) {
		// Log but don't propagate acceptable close errors
		s.Logger.Debugf("WebSocket close returned acceptable error: %v", closeErr)
		closeErr = nil
	}

	return closeErr
}

// isAcceptableCloseError checks if an error is expected during connection close
func (s *BridgeSession) isAcceptableCloseError(err error) bool {
	if err == nil {
		return true
	}

	errStr := err.Error()
	acceptableErrors := []string{
		ErrClosedNetworkConnection,
		ErrBrokenPipe,
		ErrConnectionReset,
		ErrWebSocketCloseSent,
		ErrEOF,
	}

	for _, acceptableErr := range acceptableErrors {
		if s.stringContains(errStr, acceptableErr) {
			return true
		}
	}
	return false
}

// safeCloseSSHSession provides a thread-safe way to close the SSH session.
func (s *BridgeSession) safeCloseSSHSession() error {
	if s.SSHSession == nil {
		return nil
	}

	closeErr := s.SSHSession.Close()
	if closeErr != nil && s.isAcceptableCloseError(closeErr) {
		// Log but don't propagate acceptable close errors
		s.Logger.Debugf("SSH session close returned acceptable error: %v", closeErr)
		closeErr = nil
	}
	return closeErr
}

// safeCloseSSHClient provides a thread-safe way to close the SSH client.
func (s *BridgeSession) safeCloseSSHClient() error {
	if s.SSHClient == nil {
		return nil
	}

	closeErr := s.SSHClient.Close()
	if closeErr != nil && s.isAcceptableCloseError(closeErr) {
		// Log but don't propagate acceptable close errors
		s.Logger.Debugf("SSH client close returned acceptable error: %v", closeErr)
		closeErr = nil
	}
	return closeErr
}

// initiateShutdown marks the session for shutdown and cancels the context
func (s *BridgeSession) initiateShutdown() {
	if !s.stateMachine.TransitionTo(StateClosing) {
		// If we can't transition to closing, force it
		s.stateMachine.ForceTransitionTo(StateClosing)
	}

	if s.CancelFunc != nil {
		s.CancelFunc()
	}
}

// isShuttingDown checks if the session is in shutdown state
func (s *BridgeSession) isShuttingDown() bool {
	return s.stateMachine.IsClosed()
}

// isFatalError determines if an error should cause the connection to close.
// Only certain types of errors are considered fatal and require closing the connection.
func (s *BridgeSession) isFatalError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	nonFatalPatterns := []string{
		message.ErrMsgUnknownAction,
		ErrUnmarshalError,
		ErrInvalidTerminalDimensions,
		ErrCannotResizeTerminal,
	}

	for _, pattern := range nonFatalPatterns {
		if s.stringContains(errStr, pattern) {
			return false
		}
	}

	return true
}

// stringContains checks if a string contains a substring using simple iteration.
func (s *BridgeSession) stringContains(str, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(str) < len(substr) {
		return false
	}

	for i := 0; i <= len(str)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if str[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// wsWriterLoop handles all WebSocket writes through a single goroutine
// to ensure thread-safe write operations.
func (s *BridgeSession) wsWriterLoop() {
	defer s.WaitGroup.Done()

	for {
		select {
		case msg := <-s.wsWriteChan:
			if s.stateMachine.IsClosed() {
				s.messagePool.PutWSMessage(msg)
				if msg.Data != nil {
					s.bufferPool.Put(msg.Data)
				}
				return
			}

			err := s.WebSocketConn.WriteMessage(msg.Type, msg.Data)

			if msg.Data != nil {
				s.bufferPool.Put(msg.Data)
			}
			s.messagePool.PutWSMessage(msg)

			if err != nil && !s.isAcceptableCloseError(err) {
				s.Logger.Errorf("WebSocket write error: %v", err)
				return
			}

		case <-s.shutdownChan:
			return
		case <-s.Context.Done():
			return
		}
	}
}

// controlHandler processes control signals through a dedicated channel.
func (s *BridgeSession) controlHandler() {
	defer s.WaitGroup.Done()

	for {
		select {
		case ctrl := <-s.controlChan:
			s.processControlSignal(ctrl)
			s.messagePool.PutControlSignal(ctrl)

		case <-s.shutdownChan:
			return
		case <-s.Context.Done():
			return
		}
	}
}

// processControlSignal handles different types of control operations.
func (s *BridgeSession) processControlSignal(ctrl *ControlSignal) {
	switch ctrl.Type {
	case ControlUpdateActivity:
		atomic.StoreInt64(&s.lastActivity, time.Now().Unix())
	case ControlPing:
		// Ping is handled by wsWriterLoop
	case ControlShutdown:
		s.initiateShutdown()
	case ControlForceClose:
		s.stateMachine.ForceTransitionTo(StateClosed)
	}
}

// updateLastActivity updates the timestamp of the last recorded activity.
// Uses atomic operations for thread-safe updates.
func (s *BridgeSession) updateLastActivity() {
	atomic.StoreInt64(&s.lastActivity, time.Now().Unix())
}

// WaitForCompletion blocks until the SSH session has terminated.
func (s *BridgeSession) WaitForCompletion() error {
	if s.SSHSession == nil {
		return fmt.Errorf("SSH session not initialized")
	}
	return s.SSHSession.Wait()
}

// Close terminates the session and releases all associated resources.
// Uses state machine to prevent multiple close attempts.
func (s *BridgeSession) Close() error {
	// Check if already closed/closing
	if s.stateMachine.IsClosed() {
		return nil
	}

	s.Logger.Infof("Initiating coordinated shutdown for bridge session %s", s.ID)

	// First, initiate shutdown to cancel context and stop goroutines
	s.initiateShutdown()

	// Wait for all goroutines to finish
	if s.WaitGroup != nil {
		s.WaitGroup.Wait()
	}

	var finalErr error

	// Close connections in reverse order of creation
	// 1. Close SSH session first (application level)
	if sessionErr := s.safeCloseSSHSession(); sessionErr != nil {
		s.Logger.Errorf("Error closing SSH session: %v", sessionErr)
		if finalErr == nil {
			finalErr = sessionErr
		}
	}

	// 2. Close SSH client (transport level)
	if clientErr := s.safeCloseSSHClient(); clientErr != nil {
		s.Logger.Errorf("Error closing SSH client: %v", clientErr)
		if finalErr == nil {
			finalErr = clientErr
		}
	}

	// 3. Close WebSocket connection (presentation level)
	if wsErr := s.safeCloseWebSocket(); wsErr != nil {
		s.Logger.Errorf("Error closing WebSocket connection: %v", wsErr)
		if finalErr == nil {
			finalErr = wsErr
		}
	}

	// Transition to closed state
	s.stateMachine.TransitionTo(StateClosed)
	s.Logger.Infof("Bridge session %s closed successfully", s.ID)

	return finalErr
}

// GetStats returns a map of the session's current statistics.
func (s *BridgeSession) GetStats() map[string]interface{} {
	state := s.stateMachine.GetState()

	lastActivity := time.Unix(atomic.LoadInt64(&s.lastActivity), 0)

	return map[string]interface{}{
		"id":             s.ID,
		"target_address": s.TargetAddress,
		"client_ip":      s.ClientIP,
		"state":          state.String(),
		"is_active":      s.stateMachine.IsActive(),
		"is_closed":      s.stateMachine.IsClosed(),
		"created_at":     s.CreatedAt,
		"last_activity":  lastActivity,
		"duration":       time.Since(s.CreatedAt).String(),
	}
}

// IsActive returns true if the session is currently active
func (s *BridgeSession) IsActive() bool {
	return s.stateMachine.IsActive()
}

// GetLastActivity returns the time of the last recorded activity.
func (s *BridgeSession) GetLastActivity() time.Time {
	return time.Unix(atomic.LoadInt64(&s.lastActivity), 0)
}
