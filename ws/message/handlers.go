package message

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ActionHandler defines the interface for handling action messages
type ActionHandler interface {
	Handle(session *ssh.Session, messageData []byte) error
}

// ResizeHandler handles terminal resize actions
type ResizeHandler struct {
	logger *logrus.Logger
}

// NewResizeHandler creates a new resize handler
func NewResizeHandler(logger *logrus.Logger) *ResizeHandler {
	return &ResizeHandler{
		logger: logger,
	}
}

// Handle processes the terminal resize command
func (handler *ResizeHandler) Handle(session *ssh.Session, messageData []byte) error {
	var resizeMsg ResizeMessage
	if err := json.Unmarshal(messageData, &resizeMsg); err != nil {
		return fmt.Errorf("error unmarshalling resize message: %v", err)
	}

	if handler.logger != nil {
		handler.logger.Debugf("Resizing terminal to cols: %d, rows: %d", resizeMsg.Cols, resizeMsg.Rows)
	}

	return session.WindowChange(resizeMsg.Rows, resizeMsg.Cols)
}

// PingHandler handles ping actions
type PingHandler struct {
	logger *logrus.Logger
}

// NewPingHandler creates a new ping handler
func NewPingHandler(logger *logrus.Logger) *PingHandler {
	return &PingHandler{
		logger: logger,
	}
}

// Handle processes the ping action
func (handler *PingHandler) Handle(session *ssh.Session, messageData []byte) error {
	if handler.logger != nil {
		handler.logger.Debug("Received ping action")
	}
	return nil
}

// HandlerRegistry manages action handlers
type HandlerRegistry struct {
	handlers map[ActionType]ActionHandler
	logger   *logrus.Logger
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry(logger *logrus.Logger) *HandlerRegistry {
	registry := &HandlerRegistry{
		handlers: make(map[ActionType]ActionHandler),
		logger:   logger,
	}

	// Register default handlers
	registry.RegisterHandler(ResizeAction, NewResizeHandler(logger))
	registry.RegisterHandler(PingAction, NewPingHandler(logger))

	return registry
}

// RegisterHandler registers a new action handler
func (registry *HandlerRegistry) RegisterHandler(action ActionType, handler ActionHandler) {
	registry.handlers[action] = handler
}

// HandleAction processes an action message
func (registry *HandlerRegistry) HandleAction(session *ssh.Session, action ActionType, messageData []byte) error {
	handler, exists := registry.handlers[action]
	if !exists {
		if registry.logger != nil {
			registry.logger.Debugf("Unknown action: %s", action)
		}
		return fmt.Errorf("unknown action: %s", action)
	}

	return handler.Handle(session, messageData)
}

// GetRegisteredActions returns a list of registered action types
func (registry *HandlerRegistry) GetRegisteredActions() []ActionType {
	actions := make([]ActionType, 0, len(registry.handlers))
	for action := range registry.handlers {
		actions = append(actions, action)
	}
	return actions
}
