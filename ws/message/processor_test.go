package message

import (
	"bytes"
	"strings"
	"testing"
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

func TestProcessTextMessageUnknownAction(t *testing.T) {
	p := NewMessageProcessor(nil)
	err := p.ProcessTextMessage(strings.NewReader(`{"action":"unknown"}`), nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}
