package message

// Credentials encapsulates the username and password for SSH authentication.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenericMessage is used to unmarshal the 'action' field from any JSON message
// to determine its specific type.
type GenericMessage struct {
	Action string `json:"action"`
}

// ResizeMessage defines the structure for a terminal resize command.
type ResizeMessage struct {
	Action string `json:"action"`
	Cols   int    `json:"cols"`
	Rows   int    `json:"rows"`
}

// PingMessage represents a keep-alive ping message.
type PingMessage struct {
	Action string `json:"action"`
}

// MessageType defines the type of a WebSocket message.
type MessageType int

const (
	// BinaryMessageType corresponds to a WebSocket binary message.
	BinaryMessageType MessageType = 2
	// TextMessageType corresponds to a WebSocket text message.
	TextMessageType MessageType = 1
	// PingMessageType corresponds to a WebSocket ping frame.
	PingMessageType MessageType = 9
	// PongMessageType corresponds to a WebSocket pong frame.
	PongMessageType MessageType = 10
)

// ActionType defines the type of a JSON-based action message.
type ActionType string

const (
	// ResizeAction identifies a terminal resize command.
	ResizeAction ActionType = "resize"
	// PingAction identifies a keep-alive ping command.
	PingAction ActionType = "ping"
)

// Error message constants
const (
	ErrMsgUnknownAction = "unknown action"
)
