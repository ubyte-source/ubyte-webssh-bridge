package connection

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/ubyte-source/ubyte-webssh-bridge/message"
	"github.com/ubyte-source/ubyte-webssh-bridge/ssh"
)

// BridgeSession represents a single, managed WebSocket-to-SSH connection.
// It contains all necessary state for the session, including connections,
// synchronization primitives, and metadata.
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

	WriteMutex sync.Mutex

	IsActive     bool
	IsClosed     bool
	CloseMutex   sync.RWMutex
	CreatedAt    time.Time
	LastActivity time.Time

	Logger *logrus.Logger
}

// NewBridgeSession creates and initializes a new BridgeSession.
func NewBridgeSession(id string, webSocketConn *websocket.Conn, targetAddress, clientIP string, logger *logrus.Logger) *BridgeSession {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()

	return &BridgeSession{
		ID:               id,
		TargetAddress:    targetAddress,
		ClientIP:         clientIP,
		WebSocketConn:    webSocketConn,
		MessageProcessor: message.NewMessageProcessor(logger),
		Context:          ctx,
		CancelFunc:       cancel,
		WaitGroup:        &sync.WaitGroup{},
		IsActive:         false,
		IsClosed:         false,
		CreatedAt:        now,
		LastActivity:     now,
		Logger:           logger,
	}
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

	s.WaitGroup.Add(3)
	go s.handleWebSocketMessages()
	go s.handleSSHOutput()
	go s.sendKeepAlive()

	if err := s.SSHSession.StartShell(); err != nil {
		s.Logger.Errorf("Error starting SSH shell: %v", err)
		return fmt.Errorf("failed to start SSH shell: %v", err)
	}

	s.IsActive = true
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
			s.Logger.Errorf("WebSocket frame error: %v", err)
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
			if err := s.safeCloseWebSocket(); err != nil {
				s.Logger.Errorf("Failed to close WebSocket in readNextWebSocketFrame: %v", err)
			}
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
				s.Logger.Errorf("Error writing SSH output to WebSocket: %v", writeErr)
				if closeErr := s.safeCloseWebSocket(); closeErr != nil {
					s.Logger.Errorf("Failed to close WebSocket in handleSSHOutput: %v", closeErr)
				}
				return
			}
			s.updateLastActivity()
		}

		if err != nil {
			if err != io.EOF {
				s.Logger.Errorf("Error reading SSH stdout: %v", err)
			}
			if closeErr := s.safeCloseWebSocket(); closeErr != nil {
				s.Logger.Errorf("Failed to close WebSocket in handleSSHOutput on error: %v", closeErr)
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
				s.Logger.Errorf("Error sending ping: %v", err)
				if closeErr := s.safeCloseWebSocket(); closeErr != nil {
					s.Logger.Errorf("Failed to close WebSocket in sendKeepAlive: %v", closeErr)
				}
				return
			}
		}
	}
}

// safeWriteWebSocketMessage provides a thread-safe way to write messages
// to the WebSocket connection.
func (s *BridgeSession) safeWriteWebSocketMessage(messageType int, data []byte) error {
	s.CloseMutex.RLock()
	if s.IsClosed {
		s.CloseMutex.RUnlock()
		return fmt.Errorf("connection is closed")
	}

	s.WriteMutex.Lock()
	err := s.WebSocketConn.WriteMessage(messageType, data)
	s.WriteMutex.Unlock()
	s.CloseMutex.RUnlock()

	return err
}

// safeCloseWebSocket provides a thread-safe way to close the WebSocket connection.
func (s *BridgeSession) safeCloseWebSocket() error {
	s.CloseMutex.Lock()
	defer s.CloseMutex.Unlock()
	if s.IsClosed {
		return nil // Already closed
	}
	s.IsClosed = true
	return s.WebSocketConn.Close()
}

// isFatalError determines if an error should cause the connection to close.
// Only certain types of errors are considered fatal and require closing the connection.
func (s *BridgeSession) isFatalError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific non-fatal error patterns using simple string matching
	errStr := err.Error()

	// Action processing errors are usually non-fatal
	nonFatalPatterns := []string{
		"unknown action",
		"error unmarshalling",
		"invalid terminal dimensions",
		"cannot resize terminal",
	}

	for _, pattern := range nonFatalPatterns {
		if s.stringContains(errStr, pattern) {
			return false
		}
	}

	// All other errors are considered fatal
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

// updateLastActivity updates the timestamp of the last recorded activity.
func (s *BridgeSession) updateLastActivity() {
	s.LastActivity = time.Now()
}

// WaitForCompletion blocks until the SSH session has terminated.
func (s *BridgeSession) WaitForCompletion() error {
	if s.SSHSession == nil {
		return fmt.Errorf("SSH session not initialized")
	}
	return s.SSHSession.Wait()
}

// Close terminates the session and releases all associated resources.
func (s *BridgeSession) Close() error {
	if s.CancelFunc != nil {
		s.CancelFunc()
	}
	if s.WaitGroup != nil {
		s.WaitGroup.Wait()
	}

	if s.SSHSession != nil {
		if err := s.SSHSession.Close(); err != nil {
			s.Logger.Errorf("Failed to close SSH session: %v", err)
		}
	}
	if s.SSHClient != nil {
		if err := s.SSHClient.Close(); err != nil {
			s.Logger.Errorf("Failed to close SSH client: %v", err)
		}
	}
	if err := s.safeCloseWebSocket(); err != nil {
		s.Logger.Errorf("Failed to close WebSocket: %v", err)
	}

	s.IsActive = false
	s.Logger.Infof("Bridge session %s closed", s.ID)
	return nil
}

// GetStats returns a map of the session's current statistics.
func (s *BridgeSession) GetStats() map[string]interface{} {
	s.CloseMutex.RLock()
	defer s.CloseMutex.RUnlock()

	return map[string]interface{}{
		"id":             s.ID,
		"target_address": s.TargetAddress,
		"client_ip":      s.ClientIP,
		"is_active":      s.IsActive,
		"is_closed":      s.IsClosed,
		"created_at":     s.CreatedAt,
		"last_activity":  s.LastActivity,
		"duration":       time.Since(s.CreatedAt).String(),
	}
}
