package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/coder/websocket"
	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// HostKey keeps the type and the fingerprint of the device's host key for the
// session's records.
func (s *session) HostKey(keyType, sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyType, s.keySHA = keyType, sha
}

// Sign asks the page to sign data with the agent flags and returns its signature, or
// errRefused when the page refuses.
func (s *session) Sign(ctx context.Context, data []byte, flags uint32) ([]byte, error) {
	s.signID++
	id := s.signID
	m, err := s.ask(ctx, protocol.KindSignature, protocol.EncodeSign(id, data, flags))
	if err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case protocol.Signature:
		if m.ID == id {
			return m.Blob, nil
		}
	case protocol.Refusal:
		if m.ID == id {
			return nil, errRefused
		}
	}
	return nil, s.violation()
}

// Answer asks the page the prompts of c and returns its answers, one per prompt.
func (s *session) Answer(ctx context.Context, c protocol.Challenge) ([]secret.Value, error) {
	m, err := s.ask(ctx, protocol.KindAnswers, protocol.EncodeChallenge(c))
	if err != nil {
		return nil, err
	}
	if answers, ok := m.(protocol.Answers); ok && len(answers.Values) == len(c.Prompts) {
		return answers.Values, nil
	}
	return nil, s.violation()
}

// Banner shows the page a banner of the device.
func (s *session) Banner(ctx context.Context, text string) error {
	return s.write(ctx, websocket.MessageText, protocol.EncodeBanner(text))
}

// ask writes request, marks the kind of its answer pending so that the reader lets the
// page's answer through, and returns that answer.
func (s *session) ask(ctx context.Context, kind protocol.Kind, request []byte) (protocol.Message, error) {
	s.pending.Store(uint32(kind))
	defer s.pending.Store(0)
	if err := s.write(ctx, websocket.MessageText, request); err != nil {
		return nil, err
	}
	select {
	case m := <-s.messages:
		return m, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the page: %w", context.Cause(ctx))
	}
}

// violation ends the session on an answer the page was not asked for.
func (s *session) violation() error {
	s.cancel(errViolation)
	return errViolation
}

// loginKey returns the fingerprint of the page's key when it logged in, else "".
func (s *session) loginKey() string {
	if s.client.Method() != "publickey" {
		return ""
	}
	return fingerprint(s.key)
}

// hostKeyAttrs returns the attributes of the device's host key, none before the first
// key exchange completed.
func (s *session) hostKeyAttrs() []slog.Attr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyType == "" {
		return nil
	}
	return []slog.Attr{slog.String("host_key_type", s.keyType), slog.String("host_key_sha256", s.keySHA)}
}

// fingerprint returns the SHA256 fingerprint of an SSH public-key blob as ssh-keygen
// prints it.
func fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
