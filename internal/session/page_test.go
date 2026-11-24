package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"testing/synctest"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

func TestFingerprint(t *testing.T) {
	blob := []byte("ssh-ed25519 blob of user01")
	sum := sha256.Sum256(blob)
	if got, want := fingerprint(blob), "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

func TestSessionBanner(t *testing.T) {
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.config.BannerCallback = func(ssh.ConnMetadata) string { return "Authorized use only.\r\n" }
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
	if banner := r.expect(t, "banner"); banner["text"] != "Authorized use only.\r\n" {
		t.Errorf("banner = %v", banner)
	}
	r.expect(t, "exit")
}

// TestSessionSignPageGone signs for a page that is gone: Sign returns the failed
// write at once, under a context the end of the session does not end.
func TestSessionSignPageGone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bridge, page := wsPair(t.Context(), t, plain)
		s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
			discardLogger())
		defer release()
		if err := page.CloseNow(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Sign(t.Context(), []byte("data"), 0); !errors.Is(err, errPageGone) {
			t.Errorf("Sign error = %v, want errPageGone", err)
		}
		if got := closeCode(context.Cause(sctx)); got != closeAbnormal {
			t.Errorf("close code = %d, want 1006", got)
		}
		if err := bridge.CloseNow(); err != nil {
			t.Log(err)
		}
	})
}

// TestSessionAskEnded asks a page that answers nothing under a context that ended:
// Sign and Answer return its cause.
func TestSessionAskEnded(t *testing.T) {
	cases := []struct {
		name string
		ask  func(ctx context.Context, s *session) error
	}{
		{"Sign", func(ctx context.Context, s *session) error {
			_, err := s.Sign(ctx, []byte("data"), 0)
			return err
		}},
		{"Answer", func(ctx context.Context, s *session) error {
			_, err := s.Answer(ctx, protocol.Challenge{Prompts: []protocol.Prompt{{Text: "Code: "}}})
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, release := outputSession(t)
				defer release()
				ctx, cancel := context.WithCancelCause(t.Context())
				cancel(errStopped)
				if err := c.ask(ctx, s); !errors.Is(err, errStopped) {
					t.Errorf("error = %v, want errStopped", err)
				}
			})
		})
	}
}

func TestSessionHostKey(t *testing.T) {
	s := &session{}
	if attrs := s.hostKeyAttrs(); attrs != nil {
		t.Errorf("attributes before the key exchange = %v, want none", attrs)
	}
	s.HostKey("ssh-ed25519", "SHA256:user01")
	attrs := s.hostKeyAttrs()
	if len(attrs) != 2 || attrs[0].Value.String() != "ssh-ed25519" || attrs[1].Value.String() != "SHA256:user01" {
		t.Errorf("attributes = %v", attrs)
	}
}

func TestSessionAnswerOfAnotherKind(t *testing.T) {
	r := start(t.Context(), t, testConfig(), interactiveDevice(t).listen(t))
	r.send(t, connectFrame(""))
	r.expect(t, "challenge")
	r.send(t, `{"type":"refusal","id":1}`)
	if code := r.closed(t); code != closeStatus(protocol.CloseViolation) {
		t.Errorf("close code = %d, want 1008", code)
	}
}
