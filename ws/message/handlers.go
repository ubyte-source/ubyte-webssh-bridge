package message

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ActionHandler defines the contract for types that can handle specific
// WebSocket actions, such as terminal resizing or pings.
type ActionHandler interface {
	Handle(session *ssh.Session, messageData []byte) error
}

// ResizeHandler is responsible for processing terminal resize actions.
type ResizeHandler struct {
	logger *logrus.Logger
}

// NewResizeHandler creates a new ResizeHandler.
func NewResizeHandler(logger *logrus.Logger) *ResizeHandler {
	return &ResizeHandler{logger: logger}
}

// Handle parses a resize message and applies the new dimensions to the SSH session.
func (h *ResizeHandler) Handle(session *ssh.Session, messageData []byte) error {
	var resizeMsg ResizeMessage
	if err := json.Unmarshal(messageData, &resizeMsg); err != nil {
		return fmt.Errorf("error unmarshalling resize message: %v", err)
	}

	if resizeMsg.Cols <= 0 || resizeMsg.Rows <= 0 {
		return fmt.Errorf("invalid terminal dimensions: cols=%d, rows=%d", resizeMsg.Cols, resizeMsg.Rows)
	}

	if session == nil {
		return fmt.Errorf("cannot resize terminal: SSH session is nil")
	}

	h.logger.Debugf("Resizing terminal to cols: %d, rows: %d", resizeMsg.Cols, resizeMsg.Rows)
	return session.WindowChange(resizeMsg.Rows, resizeMsg.Cols)
}

// PingHandler processes ping messages, which are used for keep-alive checks.
type PingHandler struct {
	logger *logrus.Logger
}

// NewPingHandler creates a new PingHandler.
func NewPingHandler(logger *logrus.Logger) *PingHandler {
	return &PingHandler{logger: logger}
}

// Handle logs the receipt of a ping message. The ping mechanism is primarily
// handled at the WebSocket transport layer.
func (h *PingHandler) Handle(session *ssh.Session, messageData []byte) error {
	if h.logger != nil {
		h.logger.Debug("Received ping action")
	}
	return nil
}

// HandlerRegistry holds a mapping of action types to their corresponding handlers.
type HandlerRegistry struct {
	handlers map[ActionType]ActionHandler
	logger   *logrus.Logger
}

// NewHandlerRegistry creates a new HandlerRegistry and registers the default handlers.
func NewHandlerRegistry(logger *logrus.Logger) *HandlerRegistry {
	registry := &HandlerRegistry{
		handlers: make(map[ActionType]ActionHandler),
		logger:   logger,
	}
	registry.RegisterHandler(ResizeAction, NewResizeHandler(logger))
	registry.RegisterHandler(PingAction, NewPingHandler(logger))
	return registry
}

// RegisterHandler adds or replaces a handler for a specific action type.
func (r *HandlerRegistry) RegisterHandler(action ActionType, handler ActionHandler) {
	r.handlers[action] = handler
}

// HandleAction finds the appropriate handler for a given action and invokes it.
func (r *HandlerRegistry) HandleAction(session *ssh.Session, action ActionType, messageData []byte) error {
	handler, exists := r.handlers[action]
	if !exists {
		if r.logger != nil {
			r.logger.Debugf("Unknown action: %s", action)
		}
		return fmt.Errorf("unknown action: %s", action)
	}
	return handler.Handle(session, messageData)
}

// GetRegisteredActions returns a slice of all currently registered action types.
func (r *HandlerRegistry) GetRegisteredActions() []ActionType {
	actions := make([]ActionType, 0, len(r.handlers))
	for action := range r.handlers {
		actions = append(actions, action)
	}
	return actions
}
