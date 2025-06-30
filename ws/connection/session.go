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

// BridgeSession represents a WebSocket-SSH bridge session
type BridgeSession struct {
	// Identification
	ID            string
	TargetAddress string
	ClientIP      string

	// Connections
	WebSocketConn *websocket.Conn
	SSHClient     *ssh.SSHClient
	SSHSession    *ssh.SSHSession

	// Message processing
	MessageProcessor *message.MessageProcessor

	// Context and synchronization
	Context    context.Context
	CancelFunc context.CancelFunc
	WaitGroup  *sync.WaitGroup

	// WebSocket write synchronization
	WriteMutex sync.Mutex

	// Connection state
	IsActive     bool
	IsClosed     bool
	CloseMutex   sync.RWMutex
	CreatedAt    time.Time
	LastActivity time.Time

	// Logger
	Logger *logrus.Logger
}

// NewBridgeSession creates a new bridge session
func NewBridgeSession(id string, webSocketConn *websocket.Conn, targetAddress string, clientIP string, logger *logrus.Logger) *BridgeSession {
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

// InitializeSSHConnection establishes the SSH connection for this session
func (session *BridgeSession) InitializeSSHConnection(credentials message.Credentials, timeouts ssh.SSHTimeouts) error {
	session.SSHClient = ssh.NewSSHClient(credentials, session.TargetAddress, timeouts, session.Logger)

	if err := session.SSHClient.Connect(session.Context, timeouts); err != nil {
		return fmt.Errorf("failed to connect SSH client: %v", err)
	}

	sshSession, err := session.SSHClient.NewSession()
	if err != nil {
		if closeErr := session.SSHClient.Close(); closeErr != nil && session.Logger != nil {
			session.Logger.Errorf("Failed to close SSH client after session creation error: %v", closeErr)
		}
		return fmt.Errorf("failed to create SSH session: %v", err)
	}

	session.SSHSession = sshSession
	return nil
}

// StartCommunication begins the bidirectional communication between WebSocket and SSH
func (session *BridgeSession) StartCommunication() error {
	if session.SSHSession == nil {
		return fmt.Errorf("SSH session not initialized")
	}

	// Start communication goroutines
	session.WaitGroup.Add(3)
	go session.handleWebSocketMessages()
	go session.handleSSHOutput()
	go session.sendKeepAlive()

	// Start SSH shell
	if err := session.SSHSession.StartShell(); err != nil {
		session.Logger.Errorf("Error starting SSH shell: %v", err)
		return fmt.Errorf("failed to start SSH shell: %v", err)
	}

	session.IsActive = true
	session.updateLastActivity()

	if session.Logger != nil {
		session.Logger.Infof("Bridge session %s started successfully", session.ID)
	}

	return nil
}

// handleWebSocketMessages processes incoming WebSocket messages
func (session *BridgeSession) handleWebSocketMessages() {
	defer session.WaitGroup.Done()
	defer func() {
		if stdinPipe := session.SSHSession.GetStdinPipe(); stdinPipe != nil {
			if err := stdinPipe.Close(); err != nil && session.Logger != nil {
				session.Logger.Errorf("Failed to close stdin pipe: %v", err)
			}
		}
	}()

	for {
		select {
		case <-session.Context.Done():
			return
		default:
		}

		messageType, reader, err := session.readNextWebSocketFrame()
		if err != nil {
			if session.Logger != nil {
				session.Logger.Errorf("WebSocket frame error: %v", err)
			}
			return
		}

		session.updateLastActivity()

		if err := session.processWebSocketMessage(messageType, reader); err != nil {
			if session.Logger != nil {
				session.Logger.Errorf("Message processing error: %v", err)
			}
			return
		}
	}
}

// readNextWebSocketFrame reads the next WebSocket frame with context handling
func (session *BridgeSession) readNextWebSocketFrame() (int, io.Reader, error) {
	type result struct {
		messageType int
		reader      io.Reader
		err         error
	}

	resultChannel := make(chan result, 1)

	go func() {
		messageType, reader, err := session.WebSocketConn.NextReader()
		select {
		case resultChannel <- result{messageType, reader, err}:
		case <-session.Context.Done():
			if err := session.safeCloseWebSocket(); err != nil && session.Logger != nil {
				session.Logger.Errorf("Failed to close WebSocket in readNextWebSocketFrame: %v", err)
			}
		}
	}()

	select {
	case res := <-resultChannel:
		return res.messageType, res.reader, res.err
	case <-session.Context.Done():
		return 0, nil, session.Context.Err()
	}
}

// processWebSocketMessage processes a WebSocket message based on its type
func (session *BridgeSession) processWebSocketMessage(messageType int, reader io.Reader) error {
	stdinWriter := session.SSHSession.GetStdinPipe()
	sshSession := session.SSHSession.GetSession()

	switch messageType {
	case int(message.BinaryMessageType):
		return session.MessageProcessor.ProcessBinaryMessage(reader, stdinWriter)
	case int(message.TextMessageType):
		return session.MessageProcessor.ProcessTextMessage(reader, stdinWriter, sshSession)
	default:
		// Ignore other message types
		return nil
	}
}

// handleSSHOutput reads SSH output and sends it to WebSocket
func (session *BridgeSession) handleSSHOutput() {
	defer session.WaitGroup.Done()

	stdoutPipe := session.SSHSession.GetStdoutPipe()
	buffer := make([]byte, 8192)

	for {
		select {
		case <-session.Context.Done():
			return
		default:
		}

		n, err := stdoutPipe.Read(buffer)
		if n > 0 {
			if writeErr := session.safeWriteWebSocketMessage(int(message.BinaryMessageType), buffer[:n]); writeErr != nil {
				if session.Logger != nil {
					session.Logger.Errorf("Error writing SSH output to WebSocket: %v", writeErr)
				}
				if err := session.safeCloseWebSocket(); err != nil && session.Logger != nil {
					session.Logger.Errorf("Failed to close WebSocket in handleSSHOutput: %v", err)
				}
				return
			}
			session.updateLastActivity()
		}

		if err != nil {
			if err != io.EOF && session.Logger != nil {
				session.Logger.Errorf("Error reading SSH stdout: %v", err)
			}
			if err := session.safeCloseWebSocket(); err != nil && session.Logger != nil {
				session.Logger.Errorf("Failed to close WebSocket in handleSSHOutput on error: %v", err)
			}
			return
		}
	}
}

// sendKeepAlive sends periodic ping messages to keep WebSocket alive
func (session *BridgeSession) sendKeepAlive() {
	defer session.WaitGroup.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-session.Context.Done():
			return
		case <-ticker.C:
			if err := session.safeWriteWebSocketMessage(int(message.PingMessageType), nil); err != nil {
				if session.Logger != nil {
					session.Logger.Errorf("Error sending ping: %v", err)
				}
				if err := session.safeCloseWebSocket(); err != nil && session.Logger != nil {
					session.Logger.Errorf("Failed to close WebSocket in sendKeepAlive: %v", err)
				}
				return
			}
		}
	}
}

// safeWriteWebSocketMessage writes a message to WebSocket with proper synchronization
func (session *BridgeSession) safeWriteWebSocketMessage(messageType int, data []byte) error {
	session.WriteMutex.Lock()
	defer session.WriteMutex.Unlock()

	session.CloseMutex.RLock()
	if session.IsClosed {
		session.CloseMutex.RUnlock()
		return fmt.Errorf("connection is closed")
	}
	session.CloseMutex.RUnlock()

	return session.WebSocketConn.WriteMessage(messageType, data)
}

// safeCloseWebSocket closes the WebSocket connection safely
func (session *BridgeSession) safeCloseWebSocket() error {
	session.CloseMutex.Lock()
	defer session.CloseMutex.Unlock()

	if session.IsClosed {
		return nil // Already closed
	}

	session.IsClosed = true
	return session.WebSocketConn.Close()
}

// updateLastActivity updates the last activity timestamp
func (session *BridgeSession) updateLastActivity() {
	session.LastActivity = time.Now()
}

// WaitForCompletion waits for the SSH session to complete
func (session *BridgeSession) WaitForCompletion() error {
	if session.SSHSession == nil {
		return fmt.Errorf("SSH session not initialized")
	}
	return session.SSHSession.Wait()
}

// Close closes the bridge session and cleans up all resources
func (session *BridgeSession) Close() error {
	// Cancel context to stop all goroutines
	if session.CancelFunc != nil {
		session.CancelFunc()
	}

	// Wait for all goroutines to finish
	if session.WaitGroup != nil {
		session.WaitGroup.Wait()
	}

	// Close SSH session
	if session.SSHSession != nil {
		if err := session.SSHSession.Close(); err != nil && session.Logger != nil {
			session.Logger.Errorf("Failed to close SSH session: %v", err)
		}
	}

	// Close SSH client
	if session.SSHClient != nil {
		if err := session.SSHClient.Close(); err != nil && session.Logger != nil {
			session.Logger.Errorf("Failed to close SSH client: %v", err)
		}
	}

	// Close WebSocket
	if err := session.safeCloseWebSocket(); err != nil && session.Logger != nil {
		session.Logger.Errorf("Failed to close WebSocket: %v", err)
	}

	session.IsActive = false

	if session.Logger != nil {
		session.Logger.Infof("Bridge session %s closed", session.ID)
	}

	return nil
}

// GetStats returns session statistics
func (session *BridgeSession) GetStats() map[string]interface{} {
	session.CloseMutex.RLock()
	defer session.CloseMutex.RUnlock()

	return map[string]interface{}{
		"id":             session.ID,
		"target_address": session.TargetAddress,
		"client_ip":      session.ClientIP,
		"is_active":      session.IsActive,
		"is_closed":      session.IsClosed,
		"created_at":     session.CreatedAt,
		"last_activity":  session.LastActivity,
		"duration":       time.Since(session.CreatedAt).String(),
	}
}
