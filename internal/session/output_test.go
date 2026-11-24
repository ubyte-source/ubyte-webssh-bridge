package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/sshclient"
)

func TestOutputWrite(t *testing.T) {
	s, release := outputSession(t)
	defer release()
	o := &output{ctx: t.Context(), s: s}
	chunk := bytes.Repeat([]byte("o"), 32<<10)
	if n, err := o.Write(chunk); err != nil || n != len(chunk) {
		t.Fatalf("Write = %d, %v", n, err)
	}
}

func TestOutputWriteAllocs(t *testing.T) {
	s, release := outputSession(t)
	defer release()
	o := &output{ctx: t.Context(), s: s}
	chunk := bytes.Repeat([]byte("o"), 32<<10)
	assertAllocs(t, 12, func() {
		if _, err := o.Write(chunk); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkOutputWrite(b *testing.B) {
	s, release := outputSession(b)
	defer release()
	o := &output{ctx: b.Context(), s: s}
	chunk := bytes.Repeat([]byte("o"), 32<<10)
	if n, err := o.Write(chunk); err != nil || n != len(chunk) {
		b.Fatalf("Write = %d, %v", n, err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(chunk)))
	for b.Loop() {
		if _, err := o.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}

func TestOutputWriteTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bridge, page := wsPair(t.Context(), t, plain)
		s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
			discardLogger())
		defer release()
		begin := time.Now()
		if _, err := (&output{ctx: t.Context(), s: s}).Write([]byte("output")); !errors.Is(err, errPageSilent) {
			t.Errorf("Write error = %v, want errPageSilent", err)
		}
		if got := time.Since(begin); got != 90*time.Second {
			t.Errorf("Write returned after %v, want 90s", got)
		}
		if got := closeCode(context.Cause(sctx)); got != protocol.ClosePageSilent {
			t.Errorf("close code = %d, want 4009", got)
		}
		if err := errors.Join(page.CloseNow(), bridge.CloseNow()); err != nil {
			t.Log(err)
		}
	})
}

func TestOutputWritePageGone(t *testing.T) {
	bridge, page := wsPair(t.Context(), t, plain)
	s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
		discardLogger())
	defer release()
	if err := page.CloseNow(); err != nil {
		t.Fatal(err)
	}
	if _, err := (&output{ctx: t.Context(), s: s}).Write([]byte("output")); !errors.Is(err, errPageGone) {
		t.Errorf("Write error = %v, want errPageGone", err)
	}
	if got := closeCode(context.Cause(sctx)); got != closeAbnormal {
		t.Errorf("close code = %d, want 1006", got)
	}
	if err := bridge.CloseNow(); err != nil {
		t.Log(err)
	}
}

func TestSessionForward(t *testing.T) {
	s, release := forwardSession(t, discardInput)
	defer release()
	if err := s.forward(t.Context(), bytes.Repeat([]byte("i"), 8<<10)); err != nil || s.blocked.Load() {
		t.Fatalf("forward = %v, blocked %t", err, s.blocked.Load())
	}
}

func TestSessionForwardAllocs(t *testing.T) {
	s, release := forwardSession(t, discardInput)
	defer release()
	chunk := bytes.Repeat([]byte("i"), 8<<10)
	assertAllocs(t, 12, func() {
		if err := s.forward(t.Context(), chunk); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkSessionForward(b *testing.B) {
	s, release := forwardSession(b, discardInput)
	defer release()
	chunk := bytes.Repeat([]byte("i"), 8<<10)
	if err := s.forward(b.Context(), chunk); err != nil {
		b.Fatalf("forward: %v", err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(chunk)))
	for b.Loop() {
		if err := s.forward(b.Context(), chunk); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSessionForwardInputTimeout forwards input to a device whose SSH stack froze: it
// grants the channel no room and answers nothing, and the bound ends the write with
// 4010 all the same; a deadline of 50ms stands in for the 5 minutes.
func TestSessionForwardInputTimeout(t *testing.T) {
	if inputTimeout != 5*time.Minute {
		t.Errorf("inputTimeout = %v, want 5m0s", inputTimeout)
	}
	s, release := forwardSession(t, func(d *device, _ ssh.Channel) { d.frozen.Store(true) })
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := s.forward(ctx, make([]byte, 8<<20))
	if !errors.Is(err, sshclient.ErrTargetLost) || !errors.Is(err, context.DeadlineExceeded) ||
		closeCode(err) != protocol.CloseTargetLost {
		t.Errorf("forward error = %v, want ErrTargetLost at the deadline", err)
	}
}
