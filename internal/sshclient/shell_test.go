package sshclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

func TestShellResize(t *testing.T) {
	d := newDevice(t)
	stop := make(chan struct{})
	d.run = func(ch ssh.Channel) {
		<-stop
		d.exitWith(0)(ch)
	}
	shell := openShell(t, d)
	if err := shell.Resize(protocol.Size{Cols: 132, Rows: 43}); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	var size struct{ Cols, Rows, W, H uint32 }
	if err := ssh.Unmarshal(d.waitFor("window-change"), &size); err != nil || size.Cols != 132 || size.Rows != 43 {
		t.Errorf("window-change = %+v, %v, want 132x43", size, err)
	}
	close(stop)
	if _, err := shell.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	err := shell.Resize(protocol.Size{Cols: 80, Rows: 24})
	if !errors.Is(err, ErrTargetLost) || !errors.Is(err, io.EOF) {
		t.Errorf("Resize of an ended shell error = %v, want ErrTargetLost wrapping the channel's end", err)
	}
}

func TestShellWriteIntact(t *testing.T) {
	input := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	d := newDevice(t)
	d.run = func(ch ssh.Channel) {
		got := make([]byte, len(input))
		_, err := io.ReadFull(ch, got)
		d.note(err)
		status := uint32(1)
		if sha256.Sum256(got) == sha256.Sum256(input) {
			status = 0
		}
		d.exitWith(status)(ch)
	}
	shell := openShell(t, d)
	if err := shell.Write(t.Context(), input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if exit, err := shell.Wait(); err != nil || exit.Status != 0 {
		t.Fatalf("Wait = %+v, %v, want status 0", exit, err)
	}
	if err := shell.Write(t.Context(), input[:1]); err != nil {
		t.Errorf("Write to a shell the device closed error = %v, want nil", err)
	}
}

// TestShellWriteConnectionFailed writes once a TCP keep-alive timed out under the
// shell: Wait reports ErrTargetLost, and the write drops its bytes.
func TestShellWriteConnectionFailed(t *testing.T) {
	d := newDevice(t)
	d.run = func(ssh.Channel) {}
	shell := openShell(t, d)
	d.note(pipeOf(t, shell).end.close(readError(syscall.ETIMEDOUT)))
	if _, err := shell.Wait(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("Wait error = %v, want ErrTargetLost", err)
	}
	if err := shell.Write(t.Context(), []byte("ls\r")); err != nil {
		t.Errorf("Write on a failed connection error = %v, want nil", err)
	}
}

// pipeOf returns the bridge's end of the in-memory connection of shell.
func pipeOf(t *testing.T, shell *Shell) *memConn {
	t.Helper()
	conn, ok := shell.client.conn.Conn.(*memConn)
	if !ok {
		t.Fatal("the shell's connection is no memConn")
	}
	return conn
}

// TestShellWriteEndedByContext writes to a device whose SSH stack stops: it takes no
// byte, so it grants the channel no room and answers no close; the end of ctx ends the
// write all the same, by closing the connection.
func TestShellWriteEndedByContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newDevice(t)
		d.run = func(ssh.Channel) {}
		shell := openShell(t, d)
		pipeOf(t, shell).frozen.Store(true)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		start := time.Now()
		err := shell.Write(ctx, make([]byte, 8<<20))
		if !errors.Is(err, ErrTargetLost) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Write error = %v, want ErrTargetLost by the deadline", err)
		}
		if got := time.Since(start); got != 5*time.Minute {
			t.Errorf("Write returned after %v, want 5m0s", got)
		}
	})
}

func TestShellWait(t *testing.T) {
	// exit-signal: string signal, bool core dumped, string error, string language.
	signal := append(ssh.Marshal(struct{ Signal string }{"INT"}), 0, 0, 0, 0, 0, 0, 0, 0, 0)
	cases := []struct {
		name string
		run  func(d *device, ch ssh.Channel)
		want protocol.Exit
	}{
		{"exit 0", func(d *device, ch ssh.Channel) { d.exitWith(0)(ch) }, protocol.Exit{HasStatus: true}},
		{"exit 3", func(d *device, ch ssh.Channel) { d.exitWith(3)(ch) }, protocol.Exit{Status: 3, HasStatus: true}},
		{"exit-signal INT", func(d *device, ch ssh.Channel) {
			_, err := ch.SendRequest("exit-signal", false, signal)
			d.note(errors.Join(err, ch.Close()))
		}, protocol.Exit{Signal: "INT", Status: 130, HasStatus: true}},
		{"no status", func(d *device, ch ssh.Channel) { d.note(ch.Close()) }, protocol.Exit{}},
		{"no status, then the connection closed", func(d *device, ch ssh.Channel) {
			d.note(ch.Close())
			d.cut()
		}, protocol.Exit{}},
		{"the connection closed", func(d *device, _ ssh.Channel) { d.cut() }, protocol.Exit{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t)
			d.run = func(ch ssh.Channel) { c.run(d, ch) }
			exit, err := openShell(t, d).Wait()
			if err != nil || exit != c.want {
				t.Errorf("Wait = %+v, %v, want %+v", exit, err, c.want)
			}
		})
	}
}

// TestShellWaitConnectionReset resets the connection of a shell that sent no exit
// status, after the device closed the channel or while it is open: either way the shell
// ended without status.
func TestShellWaitConnectionReset(t *testing.T) {
	cases := []struct {
		name string
		run  func(d *device, ch ssh.Channel)
	}{
		{"the channel closed first", func(d *device, ch ssh.Channel) { d.note(ch.Close()) }},
		{"the channel open", func(*device, ssh.Channel) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t)
			ran := make(chan struct{})
			d.run = func(ch ssh.Channel) {
				c.run(d, ch)
				close(ran)
			}
			shell := openShell(t, d)
			<-ran
			d.note(pipeOf(t, shell).end.close(readError(syscall.ECONNRESET)))
			if exit, err := shell.Wait(); err != nil || exit != (protocol.Exit{}) {
				t.Errorf("Wait = %+v, %v, want an exit without status", exit, err)
			}
		})
	}
}

// TestShellWaitConnectionFailed ends the connection by a TCP keep-alive that timed out,
// under a shell that sent no exit status: Wait returns ErrTargetLost.
func TestShellWaitConnectionFailed(t *testing.T) {
	d := newDevice(t)
	d.run = func(ssh.Channel) {}
	shell := openShell(t, d)
	d.note(pipeOf(t, shell).end.close(readError(syscall.ETIMEDOUT)))
	var missing *ssh.ExitMissingError
	if _, err := shell.Wait(); !errors.Is(err, ErrTargetLost) || !errors.As(err, &missing) {
		t.Fatalf("Wait error = %v, want ErrTargetLost wrapping the missing exit", err)
	}
	if err := shell.client.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Client.Close of a failed connection error = %v, want io.ErrClosedPipe", err)
	}
}

func TestShellWaitHostKeyChanged(t *testing.T) {
	d := newDevice(t)
	key := newSwitchingKey(t, 1000)
	d.config = &ssh.ServerConfig{PasswordCallback: d.config.PasswordCallback, RekeyThreshold: 256}
	d.config.AddHostKey(key)
	started := make(chan struct{})
	d.run = func(ch ssh.Channel) {
		<-started
		// The exchange under way keeps its key: a later one presents the second, and
		// the output goes on until the bridge refuses it.
		key.switchAt.Store(key.exchanges.Load() + 1)
		var err error
		for err == nil {
			_, err = ch.Write(bytes.Repeat([]byte("output of the device "), 20))
		}
		d.note(errors.Join(err, ch.Close()))
	}
	shell := openShell(t, d)
	close(started)
	if _, err := shell.Wait(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("Wait error = %v, want ErrTargetLost", err)
	}
}
