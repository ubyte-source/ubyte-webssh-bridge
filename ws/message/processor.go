package message

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// MessageProcessor handles processing of WebSocket messages
type MessageProcessor struct {
	handlerRegistry *HandlerRegistry
	logger          *logrus.Logger
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(logger *logrus.Logger) *MessageProcessor {
	return &MessageProcessor{
		handlerRegistry: NewHandlerRegistry(logger),
		logger:          logger,
	}
}

// ProcessTextMessage processes text messages (JSON actions)
func (processor *MessageProcessor) ProcessTextMessage(reader io.Reader, stdinWriter io.Writer, session *ssh.Session) error {
	// Read message data with size limit
	messageData, err := io.ReadAll(io.LimitReader(reader, 4096))
	if err != nil {
		return fmt.Errorf("error reading text message: %v", err)
	}

	// Try to parse as JSON action
	var genericMsg GenericMessage
	if err := json.Unmarshal(messageData, &genericMsg); err != nil {
		// Not a JSON action, treat as raw text input
		if processor.logger != nil {
			processor.logger.Debug("Text message is not JSON, treating as raw input")
		}
		return processor.writeToStdin(stdinWriter, messageData)
	}

	// Process as action
	actionType := ActionType(genericMsg.Action)
	return processor.handlerRegistry.HandleAction(session, actionType, messageData)
}

// ProcessBinaryMessage processes binary messages (direct terminal input)
func (processor *MessageProcessor) ProcessBinaryMessage(reader io.Reader, stdinWriter io.Writer) error {
	// Copy all binary data directly to SSH stdin
	_, err := io.Copy(stdinWriter, reader)
	if err != nil {
		return fmt.Errorf("error copying binary message to stdin: %v", err)
	}
	return nil
}

// writeToStdin writes data to SSH stdin
func (processor *MessageProcessor) writeToStdin(stdinWriter io.Writer, data []byte) error {
	_, err := stdinWriter.Write(data)
	if err != nil {
		return fmt.Errorf("error writing to stdin: %v", err)
	}
	return nil
}

// RegisterCustomHandler allows registering custom action handlers
func (processor *MessageProcessor) RegisterCustomHandler(action ActionType, handler ActionHandler) {
	processor.handlerRegistry.RegisterHandler(action, handler)
}

// GetSupportedActions returns list of supported actions
func (processor *MessageProcessor) GetSupportedActions() []ActionType {
	return processor.handlerRegistry.GetRegisteredActions()
}
