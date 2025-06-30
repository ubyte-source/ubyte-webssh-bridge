package message

// Credentials holds SSH authentication information
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenericMessage represents a message with an action field
type GenericMessage struct {
	Action string `json:"action"`
}

// ResizeMessage represents a terminal resize command
type ResizeMessage struct {
	Action string `json:"action"`
	Cols   int    `json:"cols"`
	Rows   int    `json:"rows"`
}

// PingMessage represents a ping action
type PingMessage struct {
	Action string `json:"action"`
}

// MessageType defines the type of WebSocket message
type MessageType int

const (
	// BinaryMessageType for binary data (terminal input/output)
	BinaryMessageType MessageType = 2
	// TextMessageType for JSON actions (resize, ping, etc.)
	TextMessageType MessageType = 1
	// PingMessageType for WebSocket ping frames
	PingMessageType MessageType = 9
	// PongMessageType for WebSocket pong frames
	PongMessageType MessageType = 10
)

// ActionType defines supported action types
type ActionType string

const (
	// ResizeAction for terminal resize commands
	ResizeAction ActionType = "resize"
	// PingAction for ping commands
	PingAction ActionType = "ping"
)
