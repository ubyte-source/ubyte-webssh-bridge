package message

import (
	"testing"
)

// TestResizeHandlerWithNilSession tests the nil session safety fix
func TestResizeHandlerWithNilSession(t *testing.T) {
	handler := NewResizeHandler(nil)

	// After the fix, this should return an error instead of panicking
	messageData := []byte(`{"action":"resize","cols":80,"rows":24}`)
	err := handler.Handle(nil, messageData)

	if err == nil {
		t.Fatal("Expected error when calling Handle with nil session, but got none")
	}

	expectedErrMsg := "cannot resize terminal: SSH session is nil"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message %q, got %q", expectedErrMsg, err.Error())
	}
}

// TestResizeHandlerDataValidation tests JSON and dimension validation
func TestResizeHandlerDataValidation(t *testing.T) {
	handler := NewResizeHandler(nil)

	tests := []struct {
		name        string
		data        []byte
		expectError bool
		errorMsg    string
	}{
		{
			"invalid JSON",
			[]byte(`{"invalid":json}`),
			true,
			"error unmarshalling resize message",
		},
		{
			"missing cols field",
			[]byte(`{"action":"resize","rows":24}`),
			true,
			"invalid terminal columns",
		},
		{
			"zero cols",
			[]byte(`{"action":"resize","cols":0,"rows":24}`),
			true,
			"invalid terminal columns",
		},
		{
			"negative rows",
			[]byte(`{"action":"resize","cols":80,"rows":-1}`),
			true,
			"invalid terminal rows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with nil session to trigger the validation logic
			err := handler.Handle(nil, tt.data)

			if !tt.expectError {
				t.Errorf("Expected error for %s but got none", tt.name)
				return
			}

			if err == nil {
				t.Errorf("Expected error for %s but got none", tt.name)
				return
			}

			// Check if error message contains expected substring
			if tt.errorMsg != "" && !containsSubstring(err.Error(), tt.errorMsg) {
				t.Errorf("Expected error message to contain %q, got %q", tt.errorMsg, err.Error())
			}
		})
	}
}

// Helper function to check if string contains substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestPingHandlerWithNilSession tests ping handler safety
func TestPingHandlerWithNilSession(t *testing.T) {
	handler := NewPingHandler(nil)

	// Ping handler should be safe with nil session since it doesn't use it
	messageData := []byte(`{"action":"ping"}`)
	err := handler.Handle(nil, messageData)

	if err != nil {
		t.Errorf("Ping handler should handle nil session safely, got error: %v", err)
	}
}

// TestHandlerRegistryWithInvalidData tests handlers with malformed data
func TestHandlerRegistryWithInvalidData(t *testing.T) {
	registry := NewHandlerRegistry(nil)

	tests := []struct {
		name    string
		action  ActionType
		data    []byte
		wantErr bool
	}{
		{"resize with invalid JSON", ResizeAction, []byte(`{"invalid":json}`), true},
		{"resize with missing fields", ResizeAction, []byte(`{"action":"resize"}`), true},
		{"resize with wrong types", ResizeAction, []byte(`{"action":"resize","cols":"abc","rows":"def"}`), true},
		{"ping with any data", PingAction, []byte(`anything`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.HandleAction(nil, tt.action, tt.data)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error for %s but got none", tt.name)
			} else if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}
