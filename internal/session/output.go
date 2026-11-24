package session

import (
	"context"
	"fmt"

	"github.com/coder/websocket"
)

// output writes the shell's stdout and stderr to the page, one binary frame per write,
// with the values of ctx; the WebSocket orders the writes of the two copiers.
type output struct {
	ctx context.Context //nolint:containedctx // x/crypto's copiers call Write, which takes no context
	s   *session
}

// Write writes p to the page within outputTimeout.
func (o *output) Write(p []byte) (int, error) {
	if err := o.s.write(o.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// forward writes p, input of the page, to the shell within inputTimeout; the pinger
// skips its rounds while the write waits.
func (s *session) forward(ctx context.Context, p []byte) error {
	s.blocked.Store(true)
	defer s.blocked.Store(false)
	wctx, cancel := context.WithTimeout(ctx, inputTimeout)
	defer cancel()
	if err := s.shell.Write(wctx, p); err != nil {
		return fmt.Errorf("input: %w", err)
	}
	return nil
}
