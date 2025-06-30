package message

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// MessageProcessor is responsible for interpreting and acting on messages
// received from the WebSocket client.
type MessageProcessor struct {
	handlerRegistry *HandlerRegistry
	logger          *logrus.Logger
}

// NewMessageProcessor creates a new MessageProcessor with a default set of handlers.
func NewMessageProcessor(logger *logrus.Logger) *MessageProcessor {
	return &MessageProcessor{
		handlerRegistry: NewHandlerRegistry(logger),
		logger:          logger,
	}
}

// ProcessTextMessage handles incoming text messages. It first attempts to parse
// the message as a JSON-encoded action. If successful, it dispatches the action
// to the appropriate handler. If not, it treats the message as raw terminal input.
func (p *MessageProcessor) ProcessTextMessage(reader io.Reader, stdin io.Writer, session *ssh.Session) error {
	messageData, err := io.ReadAll(io.LimitReader(reader, 4096))
	if err != nil {
		return fmt.Errorf("error reading text message: %v", err)
	}

	var genericMsg GenericMessage
	if err := json.Unmarshal(messageData, &genericMsg); err != nil {
		if p.logger != nil {
			p.logger.Debug("Text message is not a JSON action; treating as raw input.")
		}
		return p.writeToStdin(stdin, messageData)
	}

	actionType := ActionType(genericMsg.Action)
	return p.handlerRegistry.HandleAction(session, actionType, messageData)
}

// ProcessBinaryMessage handles incoming binary messages by writing them directly
// to the SSH session's standard input.
func (p *MessageProcessor) ProcessBinaryMessage(reader io.Reader, stdin io.Writer) error {
	if _, err := io.Copy(stdin, reader); err != nil {
		return fmt.Errorf("error copying binary message to stdin: %v", err)
	}
	return nil
}

// writeToStdin is a helper function to write data to the SSH session's stdin.
func (p *MessageProcessor) writeToStdin(stdin io.Writer, data []byte) error {
	if _, err := stdin.Write(data); err != nil {
		return fmt.Errorf("error writing to stdin: %v", err)
	}
	return nil
}

// RegisterCustomHandler adds a new action handler to the processor's registry.
func (p *MessageProcessor) RegisterCustomHandler(action ActionType, handler ActionHandler) {
	p.handlerRegistry.RegisterHandler(action, handler)
}

// GetSupportedActions returns a slice of all registered action types.
func (p *MessageProcessor) GetSupportedActions() []ActionType {
	return p.handlerRegistry.GetRegisteredActions()
}
