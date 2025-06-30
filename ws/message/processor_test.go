package message

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestProcessBinaryMessage(t *testing.T) {
	var buf bytes.Buffer
	p := NewMessageProcessor(nil)
	if err := p.ProcessBinaryMessage(strings.NewReader("abc"), &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "abc" {
		t.Fatalf("expected 'abc', got %q", buf.String())
	}
}

func TestProcessTextMessageRaw(t *testing.T) {
	var buf bytes.Buffer
	p := NewMessageProcessor(nil)
	if err := p.ProcessTextMessage(strings.NewReader("hello"), &buf, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "hello" {
		t.Fatalf("expected write to stdin, got %q", buf.String())
	}
}

func TestProcessTextMessagePingAction(t *testing.T) {
	p := NewMessageProcessor(nil)

	// Ping action should work fine without a session
	err := p.ProcessTextMessage(strings.NewReader(`{"action":"ping"}`), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error for ping action: %v", err)
	}
}

func TestProcessTextMessageActionParsing(t *testing.T) {
	p := NewMessageProcessor(nil)

	tests := []struct {
		name    string
		message string
		wantErr bool
	}{
		{"valid JSON format", `{"action":"ping"}`, false},
		{"valid JSON with extra fields", `{"action":"ping","extra":"field"}`, false},
		{"invalid action type", `{"action":"invalid"}`, true},
		{"missing action field", `{"other":"field"}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ProcessTextMessage(strings.NewReader(tt.message), nil, nil)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s but got none", tt.name)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tt.name, err)
				}
			}
		})
	}
}

func TestProcessTextMessageUnknownAction(t *testing.T) {
	p := NewMessageProcessor(nil)
	err := p.ProcessTextMessage(strings.NewReader(`{"action":"unknown"}`), nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestProcessTextMessageInvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	p := NewMessageProcessor(nil)

	tests := []struct {
		name        string
		message     string
		expectError bool
		expectRaw   bool
	}{
		{"malformed JSON", `{"action":}`, false, true}, // treated as raw text
		{"incomplete JSON", `{"action"`, false, true},  // treated as raw text
		{"empty braces", `{}`, true, false},            // valid JSON but missing action
		{"non-JSON text", `hello world`, false, true},  // treated as raw text
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			err := p.ProcessTextMessage(strings.NewReader(tt.message), &buf, nil)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for %s but got none", tt.name)
				}
			} else if tt.expectRaw {
				if err != nil {
					t.Fatalf("expected no error for raw text %s, got: %v", tt.name, err)
				}
				if buf.String() != tt.message {
					t.Fatalf("expected %q written to stdin, got %q", tt.message, buf.String())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tt.name, err)
				}
			}
		})
	}
}

func TestProcessTextMessageSizeLimit(t *testing.T) {
	p := NewMessageProcessor(nil)

	// Create a message larger than 4096 bytes
	largeMessage := strings.Repeat("x", 5000)
	var buf bytes.Buffer

	err := p.ProcessTextMessage(strings.NewReader(largeMessage), &buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be truncated to 4096 bytes
	if len(buf.String()) != 4096 {
		t.Fatalf("expected message to be truncated to 4096 bytes, got %d", len(buf.String()))
	}
}

func TestGetSupportedActions(t *testing.T) {
	p := NewMessageProcessor(nil)
	actions := p.GetSupportedActions()

	// Should have at least ping and resize actions
	if len(actions) == 0 {
		t.Fatal("expected at least some supported actions")
	}

	// Convert to string slice for easier checking
	actionStrings := make([]string, len(actions))
	for i, action := range actions {
		actionStrings[i] = string(action)
	}

	t.Logf("Supported actions: %v", actionStrings)
}

// testHandler implements ActionHandler for testing purposes
type testHandler struct {
	called bool
}

func (h *testHandler) Handle(session *ssh.Session, messageData []byte) error {
	h.called = true
	return nil
}

func TestRegisterCustomHandler(t *testing.T) {
	p := NewMessageProcessor(nil)

	// Register a custom handler
	customAction := ActionType("custom")
	customHandler := &testHandler{}

	p.RegisterCustomHandler(customAction, customHandler)

	// Test that our custom action is now supported
	actions := p.GetSupportedActions()
	found := false
	for _, action := range actions {
		if action == customAction {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("custom action not found in supported actions")
	}

	// Test that our custom action can be called
	err := p.ProcessTextMessage(strings.NewReader(`{"action":"custom"}`), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error processing custom action: %v", err)
	}

	if !customHandler.called {
		t.Fatal("custom handler was not called")
	}
}
