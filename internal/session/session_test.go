package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/sshclient"
)

// echoUntilExit echoes the shell's input and exits 0 at a line "exit".
func echoUntilExit(d *device, ch ssh.Channel) {
	buf := make([]byte, 4096)
	var seen []byte
	for {
		n, err := ch.Read(buf)
		if err != nil {
			d.note(err)
			return
		}
		_, err = ch.Write(buf[:n])
		d.note(err)
		seen = append(seen, buf[:n]...)
		if bytes.Contains(seen, []byte("exit\r")) {
			d.exit(ch, 0)
			return
		}
	}
}

// checkNoSecret fails t when the records hold any of secrets.
func checkNoSecret(t *testing.T, logs *logBuffer, secrets ...string) {
	t.Helper()
	text := logs.String()
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("the records hold %q: %s", s, text)
		}
	}
}

// checkPasswordRecords checks the records of a password session that exited 0.
func checkPasswordRecords(t *testing.T, logs *logBuffer) {
	t.Helper()
	started := logs.record(t, "session started")
	authenticated := logs.record(t, "session authenticated")
	ended := logs.record(t, "session ended")
	for name, want := range map[string]any{
		"level": "DEBUG", "client": testClient, "peer": testPeer, "target": started["target"],
	} {
		if started[name] != want {
			t.Errorf("session started %s = %v, want %v", name, started[name], want)
		}
	}
	for name, want := range map[string]any{
		"level": "INFO", "user": testUser, "method": "password", "host_key_type": "ssh-ed25519",
		"client": testClient,
	} {
		if authenticated[name] != want {
			t.Errorf("session authenticated %s = %v, want %v", name, authenticated[name], want)
		}
	}
	_, hasKey := authenticated["key_sha256"]
	if hasKey || !strings.HasPrefix(fmt.Sprint(authenticated["host_key_sha256"]), "SHA256:") {
		t.Errorf("session authenticated = %v", authenticated)
	}
	if ended["close_code"] != float64(1000) || ended["exit_status"] != float64(0) || ended["duration"] == nil {
		t.Errorf("session ended = %v", ended)
	}
}

func TestRunPasswordSession(t *testing.T) {
	d := newDevice(t, echoUntilExit)
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	if err := r.page.Write(t.Context(), websocket.MessageBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if typ, data := r.next(t); typ != websocket.MessageBinary || string(data) != "hello" {
		t.Fatalf("echo = %d %q, want hello", typ, data)
	}
	r.send(t, `{"type":"resize","cols":132,"rows":43}`)
	if got := <-d.resized; got != [2]uint32{132, 43} {
		t.Errorf("window-change = %v, want 132x43", got)
	}
	if err := r.page.Write(t.Context(), websocket.MessageBinary, []byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	if exit := r.expect(t, "exit"); exit["status"] != float64(0) {
		t.Errorf("exit = %v, want status 0", exit)
	}
	if code := r.closed(t); code != websocket.StatusNormalClosure {
		t.Errorf("close code = %d, want 1000", code)
	}
	checkPasswordRecords(t, r.logs)
	checkNoSecret(t, r.logs, testPassword, "hello")
}

func TestRunPublicKey(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{edKey, rsaKey} {
		keyring, blob := newAgent(t, key)
		d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 3) })
		d.config.PasswordCallback = nil
		d.config.PublicKeyCallback = func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), blob) {
				return &ssh.Permissions{}, nil
			}
			return nil, errRefusedByDevice
		}
		r := start(t.Context(), t, testConfig(), d.listen(t))
		r.loginWithKey(t, connectFrame(`,"key":"`+base64Std(blob)+`"`), keyring)
		if exit := r.expect(t, "exit"); exit["status"] != float64(3) {
			t.Errorf("exit = %v, want status 3", exit)
		}
		r.closed(t)
		authenticated := r.logs.record(t, "session authenticated")
		if authenticated["method"] != "publickey" || authenticated["key_sha256"] != fingerprint(blob) {
			t.Errorf("session authenticated = %v", authenticated)
		}
	}
}

func TestSessionResizeFailed(t *testing.T) {
	s, release := forwardSession(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	defer release()
	if _, err := s.shell.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	logs := &logBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s.resize(t.Context(), protocol.Size{Cols: 80, Rows: 24})
	if failed := logs.record(t, "resize failed"); failed["error"] == nil || s.size.Cols != 80 {
		t.Errorf("resize failed = %v", failed)
	}
}

func TestRunKeyboardInteractive(t *testing.T) {
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.config.PasswordCallback = nil
	d.config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, c ssh.KeyboardInteractiveChallenge) (
		*ssh.Permissions, error,
	) {
		answers, err := c("Two-factor", "", []string{"Code: "}, []bool{true})
		if err != nil || !slices.Equal(answers, []string{"123456"}) {
			return nil, errRefusedByDevice
		}
		return &ssh.Permissions{}, nil
	}
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.send(t, connectFrame(""))
	r.send(t, `{"type":"resize","cols":100,"rows":30}`)
	r.expect(t, "challenge")
	r.send(t, `{"type":"answers","answers":["123456"]}`)
	r.expect(t, "ready")
	r.expect(t, "exit")
	if code := r.closed(t); code != websocket.StatusNormalClosure {
		t.Errorf("close code = %d, want 1000", code)
	}
	if got := r.logs.record(t, "session authenticated")["method"]; got != "keyboard-interactive" {
		t.Errorf("method = %v", got)
	}
	checkNoSecret(t, r.logs, "123456")
}

func TestRunViolations(t *testing.T) {
	cases := []struct {
		name  string
		play  func(t *testing.T, r *run)
		value string
	}{
		{"a binary frame before ready", func(t *testing.T, r *run) {
			t.Helper()
			if err := r.page.Write(t.Context(), websocket.MessageBinary, []byte("ls\r")); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"a resize before connect", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, `{"type":"resize","cols":1,"rows":1}`)
		}, ""},
		{"answers before connect", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, `{"type":"answers","answers":[]}`)
		}, ""},
		{"an invalid connect", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, connectFrame(`,"password":"`+strings.Repeat("secret01", 200)+`"`))
		}, "secret01"},
		{"two connects", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, connectFrame(""))
			r.send(t, connectFrame(""))
		}, ""},
		{"answers of the wrong count", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, connectFrame(""))
			r.expect(t, "challenge")
			r.send(t, `{"type":"answers","answers":["answer01"]}`)
		}, "answer01"},
		{"invalid answers", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, connectFrame(""))
			r.expect(t, "challenge")
			r.send(t, `{"type":"answers","answers":["answer01",1]}`)
		}, "answer01"},
		{"a signature while a challenge is pending", func(t *testing.T, r *run) {
			t.Helper()
			r.send(t, connectFrame(""))
			r.expect(t, "challenge")
			r.send(t, `{"type":"signature","id":1,"signature":"AAAA"}`)
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := start(t.Context(), t, testConfig(), interactiveDevice(t).listen(t))
			c.play(t, r)
			if code := r.closed(t); code != websocket.StatusPolicyViolation {
				t.Errorf("close code = %d, want 1008", code)
			}
			if c.value != "" {
				checkNoSecret(t, r.logs, c.value)
			}
		})
	}
}

func TestRunSignatureOfAnotherID(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, blob := newAgent(t, key)
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.config.PublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}
	target := d.listen(t)
	for _, reply := range []string{`{"type":"signature","id":2,"signature":"AAAA"}`, `{"type":"refusal","id":2}`} {
		r := start(t.Context(), t, testConfig(), target)
		r.send(t, connectFrame(`,"key":"`+base64Std(blob)+`"`))
		r.expect(t, "sign")
		r.send(t, reply)
		if code := r.closed(t); code != websocket.StatusPolicyViolation {
			t.Errorf("%s: close code = %d, want 1008", reply, code)
		}
	}
}

func TestRunRefusalMovesOn(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, blob := newAgent(t, key)
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.config.PublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.send(t, connectFrame(`,"password":"`+testPassword+`","key":"`+base64Std(blob)+`"`))
	r.expect(t, "sign")
	r.send(t, `{"type":"refusal","id":1}`)
	r.expect(t, "ready")
	r.expect(t, "exit")
	if got := r.logs.record(t, "session authenticated")["method"]; got != "password" {
		t.Errorf("method = %v, want password", got)
	}
}

// refusedAddress refuses every connection: port 1 is privileged, and no test binds it.
const refusedAddress = "127.0.0.1:1"

func TestRunFailures(t *testing.T) {
	refusing := newDevice(t, nil)
	refusing.config.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, errRefusedByDevice
	}
	cases := []struct {
		name   string
		target string
		code   websocket.StatusCode
		level  string
		key    bool
	}{
		{"a refused password", refusing.listen(t), 4002, "DEBUG", true},
		{"a closed port", refusedAddress, 4003, "WARN", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := start(t.Context(), t, testConfig(), c.target)
			r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
			if code := r.refuseChallenges(t); code != c.code {
				t.Errorf("close code = %d, want %d", code, c.code)
			}
			failed := r.logs.record(t, "session failed")
			_, hasKey := failed["host_key_sha256"]
			if failed["level"] != c.level || failed["close_code"] != float64(c.code) || hasKey != c.key ||
				failed["peer"] != testPeer || failed["error"] == nil {
				t.Errorf("session failed = %v", failed)
			}
			checkNoSecret(t, r.logs, testPassword)
		})
	}
}

func TestRunStopped(t *testing.T) {
	d := newDevice(t, echoUntilExit)
	ctx, cancel := context.WithCancel(t.Context())
	r := start(ctx, t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	cancel()
	if code := r.closed(t); code != websocket.StatusGoingAway {
		t.Errorf("close code = %d, want 1001", code)
	}
}

func TestRunPasteAndOutputIntact(t *testing.T) {
	const size = 1 << 20
	input := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	d := newDevice(t, func(d *device, ch ssh.Channel) {
		got := make([]byte, size)
		_, err := io.ReadFull(ch, got)
		d.note(err)
		_, err = ch.Write(got)
		d.note(err)
		d.exit(ch, 0)
	})
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	var wg sync.WaitGroup
	wg.Go(func() {
		for chunk := range slices.Chunk(input, 8192) {
			if err := r.page.Write(t.Context(), websocket.MessageBinary, chunk); err != nil {
				t.Error(err)
				return
			}
		}
	})
	var received []byte
	for len(received) < size {
		typ, data := r.next(t)
		if typ == websocket.MessageBinary {
			received = append(received, data...)
		}
	}
	wg.Wait()
	if sha256.Sum256(received) != sha256.Sum256(input) {
		t.Error("the output differs from the input")
	}
	r.expect(t, "exit")
}

func TestRunNoConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		begin := time.Now()
		r := start(t.Context(), t, testConfig(), "192.0.2.10:22")
		if code := r.closed(t); code != websocket.StatusPolicyViolation {
			t.Errorf("close code = %d, want 1008", code)
		}
		if got := time.Since(begin); got != 10*time.Second {
			t.Errorf("closed after %v, want 10s", got)
		}
	})
}

// TestSessionPingWithoutPong mutes the page: the page sees the close with 4009 at the
// first ping's pongTimeout, 120 seconds in.
func TestSessionPingWithoutPong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testConfig()
		cfg.WS.HandshakeTimeout = 5 * time.Minute
		begin := time.Now()
		muted := &mutedConn{}
		r := startWith(t.Context(), t, cfg, "192.0.2.10:22", func(conn net.Conn) net.Conn {
			muted.Conn = conn
			return muted
		})
		muted.muted.Store(true)
		type end struct {
			code  websocket.StatusCode
			after time.Duration
		}
		ends := make(chan end, 1)
		go func() {
			for {
				if _, _, err := r.page.Read(t.Context()); err != nil {
					ends <- end{websocket.CloseStatus(err), time.Since(begin)}
					return
				}
			}
		}()
		time.Sleep(120 * time.Second)
		synctest.Wait()
		select {
		case e := <-ends:
			if e.code != closeStatus(protocol.ClosePageSilent) || e.after != 120*time.Second {
				t.Errorf("close code %d after %v, want 4009 after 120s", e.code, e.after)
			}
		default:
			t.Fatal("the page saw no close at 120s")
		}
		<-r.done
		if failed := r.logs.record(t, "session failed"); failed["close_code"] != float64(4009) {
			t.Errorf("session failed = %v", failed)
		}
	})
}

// TestSessionPingSkippedWhileBlocked blocks the forwarder for 10 minutes, in which no
// ping goes out, then frees it: the next ping, which the page never reads, ends the
// session.
func TestSessionPingSkippedWhileBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bridge, page := wsPair(t.Context(), t, plain)
		s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
			discardLogger())
		s.blocked.Store(true)
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.ping(sctx)
		}()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if context.Cause(sctx) != nil {
			t.Errorf("the session ended: %v", context.Cause(sctx))
		}
		s.blocked.Store(false)
		time.Sleep(pingInterval + pongTimeout)
		synctest.Wait()
		if got := context.Cause(sctx); !errors.Is(got, errPageSilent) {
			t.Errorf("end = %v, want errPageSilent", got)
		}
		release()
		<-done
		if err := errors.Join(page.CloseNow(), bridge.CloseNow()); err != nil {
			t.Log(err)
		}
	})
}

func TestCloseCode(t *testing.T) {
	cases := []struct {
		err  error
		want protocol.CloseCode
	}{
		{exitError{}, protocol.CloseNormal},
		{errStopped, protocol.CloseGoingAway},
		{errViolation, protocol.CloseViolation},
		{protocol.ErrInvalidMessage, protocol.CloseViolation},
		{sshclient.ErrInvalidKey, protocol.CloseViolation},
		{sshclient.ErrAuthFailed, protocol.CloseAuthFailed},
		{sshclient.ErrUnreachable, protocol.CloseUnreachable},
		{sshclient.ErrHandshake, protocol.CloseHandshakeFailed},
		{sshclient.ErrLoginTimeout, protocol.CloseLoginTimeout},
		{sshclient.ErrShellRefused, protocol.CloseShellRefused},
		{errPageSilent, protocol.ClosePageSilent},
		{sshclient.ErrTargetLost, protocol.CloseTargetLost},
		{errPageGone, closeAbnormal},
		{fmt.Errorf("dial: %w", errors.Join(errPageGone, sshclient.ErrUnreachable)), closeAbnormal},
		{errors.Join(errPageGone, fmt.Errorf("read: %w", websocket.ErrMessageTooBig)), closeTooBig},
	}
	for _, c := range cases {
		if got := closeCode(c.err); got != c.want {
			t.Errorf("closeCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestSessionServeDropsTheConnect(t *testing.T) {
	d := newDevice(t, echoUntilExit)
	target := d.listen(t)
	bridge, page := wsPair(t.Context(), t, plain)
	s, sctx, release := newSession(t.Context(), bridge, testConfig(), target, testClient, "", discardLogger())
	r := &run{page: page}
	var wg sync.WaitGroup
	wg.Go(func() { s.read(sctx) })
	wg.Go(func() {
		r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
		for {
			if _, _, err := page.Read(t.Context()); err != nil {
				return
			}
		}
	})
	if err := s.serve(sctx, &wg); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !s.connect.Login.Password.IsZero() || s.connect.Login.User != "" {
		t.Error("the session holds the connect after Dial")
	}
	s.cancel(errStopped)
	s.finish(t.Context(), context.Cause(sctx), &wg)
	release()
}

func TestExitErrorError(t *testing.T) {
	if got := (exitError{}).Error(); got != "session: shell exited" {
		t.Errorf("Error() = %q", got)
	}
}

func TestRunShellRefused(t *testing.T) {
	for _, refused := range []string{"pty-req", "shell"} {
		d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
		d.refuse = refused
		r := start(t.Context(), t, testConfig(), d.listen(t))
		r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
		if code := r.closed(t); code != closeStatus(protocol.CloseShellRefused) {
			t.Errorf("%s refused: close code = %d, want 4006", refused, code)
		}
	}
}

// TestRunOpeningTimesOut logs in to a device that never answers the PTY request: the
// login's deadline ends the opening of the shell with 4005.
func TestRunOpeningTimesOut(t *testing.T) {
	d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
	d.held = "pty-req"
	cfg := testConfig()
	cfg.SSH.LoginTimeout = time.Second
	r := start(t.Context(), t, cfg, d.listen(t))
	r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
	if code := r.closed(t); code != closeStatus(protocol.CloseLoginTimeout) {
		t.Errorf("close code = %d, want 4005", code)
	}
	if ended := r.logs.record(t, "session ended"); ended["close_code"] != float64(protocol.CloseLoginTimeout) {
		t.Errorf("session ended = %v, want close_code 4005", ended)
	}
}

// TestRunOpeningEnds ends a session while the device keeps the PTY request unanswered:
// Run returns at once, closed as the end says.
func TestRunOpeningEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(r *run, stop context.CancelFunc) error
		code protocol.CloseCode
	}{
		{"the page leaves", func(r *run, _ context.CancelFunc) error { return r.page.CloseNow() }, closeAbnormal},
		{"the server stops", func(_ *run, stop context.CancelFunc) error {
			stop()
			return nil
		}, protocol.CloseGoingAway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
			d.held = "pty-req"
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			r := start(ctx, t, testConfig(), d.listen(t))
			r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
			drain(r.page)
			<-d.asked
			if err := c.end(r, stop); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return within 5s of the end")
			}
			if ended := r.logs.record(t, "session ended"); ended["close_code"] != float64(c.code) {
				t.Errorf("session ended = %v, want close_code %d", ended, c.code)
			}
		})
	}
}

// TestSessionOpenAppliesTheSizeSentMeanwhile sends a resize while the device keeps the
// PTY request unanswered: the shell gets that size once it opened.
func TestSessionOpenAppliesTheSizeSentMeanwhile(t *testing.T) {
	d := newDevice(t, echoUntilExit)
	d.held = "pty-req"
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.send(t, connectFrame(`,"password":"`+testPassword+`"`))
	<-d.asked
	drain(r.page)
	r.send(t, `{"type":"resize","cols":132,"rows":43}`)
	if err := r.page.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	d.answer()
	if got := <-d.resized; got != [2]uint32{132, 43} {
		t.Errorf("window-change = %v, want 132x43", got)
	}
}

// pageEnd reads the page's frames until the WebSocket closes and returns the terminal
// bytes, the exit message, nil when none came, and the close code.
func (r *run) pageEnd(t *testing.T) (shown []byte, exit map[string]any, code websocket.StatusCode) {
	t.Helper()
	for {
		typ, data, err := r.page.Read(t.Context())
		if err != nil {
			<-r.done
			return shown, exit, websocket.CloseStatus(err)
		}
		if typ == websocket.MessageBinary {
			shown = append(shown, data...)
			continue
		}
		if bytes.HasPrefix(data, []byte(`{"type":"exit"`)) {
			exit = map[string]any{"frame": string(data)}
		}
	}
}

// TestRunExitWithoutStatus ends shells that send no exit status once the user typed:
// the device closing the shell or not, then closing or resetting the connection, ends
// with exit without status and 1000.
func TestRunExitWithoutStatus(t *testing.T) {
	cases := []struct {
		name string
		end  func(d *device, ch ssh.Channel)
	}{
		{"the shell closed, then the connection", func(d *device, ch ssh.Channel) {
			d.note(ch.Close())
			d.cut()
		}},
		{"the shell closed, then the connection reset", func(d *device, ch ssh.Channel) {
			d.note(ch.Close())
			d.reset()
		}},
		{"the connection closed", func(d *device, _ ssh.Channel) { d.cut() }},
		{"the connection reset", func(d *device, _ ssh.Channel) { d.reset() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, func(d *device, ch ssh.Channel) {
				_, err := ch.Read(make([]byte, 1))
				d.note(err)
				_, err = ch.Write([]byte("bye\r\n"))
				d.note(err)
				c.end(d, ch)
			})
			r := start(t.Context(), t, testConfig(), d.listen(t))
			r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
			if err := r.page.Write(t.Context(), websocket.MessageBinary, []byte("exit\r")); err != nil {
				t.Fatal(err)
			}
			shown, exit, code := r.pageEnd(t)
			if string(shown) != "bye\r\n" || exit["frame"] != `{"type":"exit"}` ||
				code != websocket.StatusNormalClosure {
				t.Errorf("terminal bytes %q, exit %v, close code %d, want bye, an exit without status and 1000",
					shown, exit, code)
			}
			ended := r.logs.record(t, "session ended")
			if ended["close_code"] != float64(1000) || ended["exit_status"] != nil {
				t.Errorf("session ended = %v, want close_code 1000 and no exit_status", ended)
			}
		})
	}
}

// TestRunInputAfterExit sends more input than the device's 2 MiB window while the shell
// exits 0, its output unread, so a write meets the closed channel: the page gets the
// output, the exit status and 1000.
func TestRunInputAfterExit(t *testing.T) {
	d := newDevice(t, func(d *device, ch ssh.Channel) {
		_, err := ch.Read(make([]byte, 1))
		d.note(err)
		_, err = ch.Write([]byte("bye\r\n"))
		d.note(err)
		d.exit(ch, 0)
	})
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	input := make([]byte, protocol.MaxMessageBytes)
	for range 2<<20/protocol.MaxMessageBytes + 1 {
		if err := r.page.Write(t.Context(), websocket.MessageBinary, input); err != nil {
			t.Fatal(err)
		}
	}
	shown, exit, code := r.pageEnd(t)
	if string(shown) != "bye\r\n" || exit["frame"] != `{"type":"exit","status":0}` ||
		code != websocket.StatusNormalClosure {
		t.Errorf("terminal bytes %q, exit %v, close code %d, want bye, status 0 and 1000", shown, exit, code)
	}
	ended := r.logs.record(t, "session ended")
	if ended["close_code"] != float64(1000) || ended["exit_status"] != float64(0) {
		t.Errorf("session ended = %v, want close_code 1000 and exit_status 0", ended)
	}
}

// typeThrough reads the page's frames until the WebSocket closes, writing a key before
// each read and two once the exit came, each write waiting for the bridge to read it,
// and returns the terminal bytes, the exit message and the close code.
func (r *run) typeThrough(t *testing.T) (shown, exit []byte, code websocket.StatusCode) {
	t.Helper()
	keys := 1
	for {
		for range keys {
			if err := r.page.Write(t.Context(), websocket.MessageBinary, []byte("x")); err != nil {
				t.Fatalf("page write: %v", err)
			}
		}
		typ, data, err := r.page.Read(t.Context())
		if err != nil {
			<-r.done
			return shown, exit, websocket.CloseStatus(err)
		}
		if typ == websocket.MessageBinary {
			shown = append(shown, data...)
			continue
		}
		exit, keys = data, 2
	}
}

// TestRunInputThroughTheClose types into a shell that prints 1 MiB and exits 0, the
// page reading on only once the bridge read its keys, so input left unread holds the
// page: it gets every output byte, the exit status and 1000.
func TestRunInputThroughTheClose(t *testing.T) {
	printed := bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16)
	d := newDevice(t, func(d *device, ch ssh.Channel) {
		_, err := ch.Read(make([]byte, 1))
		d.note(err)
		_, err = ch.Write(printed)
		d.note(err)
		d.exit(ch, 0)
	})
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	shown, exit, code := r.typeThrough(t)
	if !bytes.Equal(shown, printed) || string(exit) != `{"type":"exit","status":0}` ||
		code != websocket.StatusNormalClosure {
		t.Errorf("terminal bytes %d of %d, exit %q, close code %d, want all, status 0 and 1000",
			len(shown), len(printed), exit, code)
	}
	ended := r.logs.record(t, "session ended")
	if ended["close_code"] != float64(1000) || ended["exit_status"] != float64(0) {
		t.Errorf("session ended = %v, want close_code 1000 and exit_status 0", ended)
	}
}

// socketConn is the page's end of a pipe as a TCP socket holds it: a receive buffer
// takes the bridge's bytes as they come, the page waits pause before each read of it,
// and a write that meets the bridge's closed end drops all the page has not read.
type socketConn struct {
	net.Conn

	chunks chan []byte
	rest   []byte
	pause  time.Duration
	reset  atomic.Bool
}

// newSocketConn returns conn as a socket whose buffer takes the bridge's bytes until
// the bridge's end closes.
func newSocketConn(conn net.Conn, pause time.Duration) *socketConn {
	c := &socketConn{Conn: conn, chunks: make(chan []byte, 1<<10), pause: pause}
	go func() {
		defer close(c.chunks)
		for {
			chunk := make([]byte, 64<<10)
			n, err := conn.Read(chunk)
			if err != nil {
				return
			}
			c.chunks <- chunk[:n]
		}
	}()
	return c
}

// Read reads from the receive buffer once pause passed, or fails once the connection
// reset.
func (c *socketConn) Read(p []byte) (int, error) {
	time.Sleep(c.pause)
	if c.reset.Load() {
		return 0, syscall.ECONNRESET
	}
	if len(c.rest) == 0 {
		chunk, ok := <-c.chunks
		if !ok {
			return 0, io.EOF
		}
		c.rest = chunk
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write writes p to the bridge; a write that meets the bridge's closed end resets the
// connection.
func (c *socketConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.reset.Store(true)
		return n, fmt.Errorf("page: %w", err)
	}
	return n, nil
}

// exitedSession returns a session over a pipe, the page's end through wrap, whose shell
// wrote printed and exited 0, and the cause of its end; its reader runs in wg.
func exitedSession(t *testing.T, wrap func(net.Conn) net.Conn, printed []byte, wg *sync.WaitGroup) (
	s *session, page *websocket.Conn, cause error,
) {
	t.Helper()
	bridge, page := wsPair(t.Context(), t, wrap)
	s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
		discardLogger())
	t.Cleanup(release)
	wg.Go(func() { s.read(sctx) })
	for chunk := range slices.Chunk(printed, 32<<10) {
		if _, err := (&output{ctx: sctx, s: s}).Write(chunk); err != nil {
			t.Fatalf("output: %v", err)
		}
	}
	cause = exitError{exit: protocol.Exit{HasStatus: true}}
	s.cancel(cause)
	return s, page, cause
}

// finishing runs finish on s with cause and wg, as Run does once the session ended, and
// returns the page's run, done when finish returned.
func finishing(t *testing.T, s *session, page *websocket.Conn, cause error, wg *sync.WaitGroup) *run {
	t.Helper()
	r := &run{page: page, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		s.finish(t.Context(), cause, wg)
	}()
	return r
}

// TestSessionFinishSlowPage ends a session that printed 1 MiB to a page that waits
// 100ms before each read of its socket and types a key before each frame, past coder's
// 5s wait for its close frame: it gets every output byte, the exit status and 1000.
func TestSessionFinishSlowPage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		printed := bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16)
		var wg sync.WaitGroup
		s, page, cause := exitedSession(t, func(conn net.Conn) net.Conn {
			return newSocketConn(conn, 100*time.Millisecond)
		}, printed, &wg)
		begin := time.Now()
		shown, exit, code := finishing(t, s, page, cause, &wg).typeThrough(t)
		if !bytes.Equal(shown, printed) || string(exit) != `{"type":"exit","status":0}` ||
			code != websocket.StatusNormalClosure {
			t.Errorf("terminal bytes %d of %d, exit %q, close code %d, want all, status 0 and 1000",
				len(shown), len(printed), exit, code)
		}
		if took := time.Since(begin); took <= 5*time.Second || took >= pongTimeout {
			t.Errorf("the page took %v, want more than 5s and less than pongTimeout", took)
		}
	})
}

// TestSessionFinishSilentPage ends a session whose page reads on but answers nothing
// once it read the exit: the close comes at pongTimeout, 90 seconds after the exit.
func TestSessionFinishSilentPage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		muted := &mutedConn{}
		var wg sync.WaitGroup
		s, page, cause := exitedSession(t, func(conn net.Conn) net.Conn {
			muted.Conn = conn
			return muted
		}, nil, &wg)
		muted.muted.Store(true)
		begin := time.Now()
		_, exit, code := finishing(t, s, page, cause, &wg).pageEnd(t)
		if exit["frame"] != `{"type":"exit","status":0}` || code != websocket.StatusNormalClosure ||
			time.Since(begin) != 90*time.Second {
			t.Errorf("exit %v, close code %d after %v, want status 0 and 1000 after 90s", exit, code,
				time.Since(begin))
		}
	})
}

// TestRunSettleEnds ends the wait for the pong behind the exit, the page muted once it
// read the exit: Run returns at once, and the session ends with 1000.
func TestRunSettleEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(r *run, stop context.CancelFunc) error
		code websocket.StatusCode
	}{
		{"the page leaves", func(r *run, _ context.CancelFunc) error { return r.page.CloseNow() }, -1},
		{"the server stops", func(_ *run, stop context.CancelFunc) error {
			stop()
			return nil
		}, websocket.StatusNormalClosure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, func(d *device, ch ssh.Channel) { d.exit(ch, 0) })
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			muted := &mutedConn{}
			r := startWith(ctx, t, testConfig(), d.listen(t), func(conn net.Conn) net.Conn {
				muted.Conn = conn
				return muted
			})
			r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
			r.expect(t, "exit")
			muted.muted.Store(true)
			codes := make(chan websocket.StatusCode, 1)
			go func() { codes <- r.closed(t) }()
			waitSelect("websocket.(*Conn).ping(")
			if err := c.end(r, stop); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return within 5s of the end")
			}
			code, ended := <-codes, r.logs.record(t, "session ended")
			if code != c.code || ended["close_code"] != float64(1000) || ended["exit_status"] != float64(0) {
				t.Errorf("close code %d, session ended = %v, want %d, close_code 1000 and exit_status 0", code,
					ended, c.code)
			}
		})
	}
}

// TestRunMessageBounds sends a binary message of 65536 bytes and one of 65537 before
// the connect: the page and the record read 1008 for the first, 1009 for the second.
func TestRunMessageBounds(t *testing.T) {
	cases := []struct {
		size int
		want protocol.CloseCode
	}{
		{protocol.MaxMessageBytes, protocol.CloseViolation},
		{protocol.MaxMessageBytes + 1, closeTooBig},
	}
	for _, c := range cases {
		r := start(t.Context(), t, testConfig(), "192.0.2.10:22")
		if err := r.page.Write(t.Context(), websocket.MessageBinary, make([]byte, c.size)); err != nil {
			t.Fatal(err)
		}
		if code := r.closed(t); code != closeStatus(c.want) {
			t.Errorf("a message of %d bytes: close code = %d, want %d", c.size, code, c.want)
		}
		if failed := r.logs.record(t, "session failed"); failed["close_code"] != float64(c.want) {
			t.Errorf("a message of %d bytes: session failed = %v, want close_code %d", c.size, failed, c.want)
		}
	}
}

func TestRunPageGone(t *testing.T) {
	d := newDevice(t, echoUntilExit)
	r := start(t.Context(), t, testConfig(), d.listen(t))
	r.login(t, connectFrame(`,"password":"`+testPassword+`"`))
	if err := r.page.CloseNow(); err != nil {
		t.Fatal(err)
	}
	<-r.done
	if ended := r.logs.record(t, "session ended"); ended["close_code"] != float64(closeAbnormal) {
		t.Errorf("session ended = %v, want close_code 1006", ended)
	}
}

// TestSessionReadEnded reads answers the page was not asked for once the session's
// context ended: the reader drops them, cleared, and ends when the WebSocket does.
func TestSessionReadEnded(t *testing.T) {
	bridge, page := wsPair(t.Context(), t, plain)
	s, _, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
		discardLogger())
	defer release()
	ended := make(chan error, 1)
	s.cancel = func(err error) { ended <- err }
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errStopped)
	go s.read(ctx)
	r := &run{page: page}
	r.send(t, `{"type":"answers","answers":["answer01"]}`)
	if err := page.CloseNow(); err != nil {
		t.Fatal(err)
	}
	if err := <-ended; !errors.Is(err, errPageGone) {
		t.Errorf("end = %v, want errPageGone", err)
	}
	if bytes.Contains(s.buf, []byte("answer01")) {
		t.Error("the read buffer holds the dropped frame")
	}
	if err := bridge.CloseNow(); err != nil {
		t.Log(err)
	}
}

// stallConn is the page's end of a pipe whose next read, once stalled, takes one byte
// and holds until the close: a page that stops reading inside a frame.
type stallConn struct {
	net.Conn

	stalled chan struct{}
	closed  chan struct{}
	once    sync.Once
	stall   atomic.Bool
}

// Read reads into p, or one byte held until the close once stalled.
func (c *stallConn) Read(p []byte) (int, error) {
	if !c.stall.CompareAndSwap(true, false) {
		n, err := c.Conn.Read(p)
		if err != nil {
			return n, fmt.Errorf("page: %w", err)
		}
		return n, nil
	}
	n, err := c.Conn.Read(p[:1])
	close(c.stalled)
	<-c.closed
	if err != nil {
		return n, fmt.Errorf("page: %w", err)
	}
	return n, nil
}

// Close frees a held read and closes the connection.
func (c *stallConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	if err := c.Conn.Close(); err != nil {
		return fmt.Errorf("page: %w", err)
	}
	return nil
}

// waitSelect waits until a goroutine waits in a select of fn, its innermost frame.
func waitSelect(fn string) {
	buf := make([]byte, 1<<20)
	for {
		stacks := string(buf[:runtime.Stack(buf, true)])
		for g := range strings.SplitSeq(stacks, "\n\n") {
			header, frames, _ := strings.Cut(g, "\n")
			innermost, _, _ := strings.Cut(frames, "\n")
			if strings.Contains(header, " [select") && strings.Contains(innermost, fn) {
				return
			}
		}
		runtime.Gosched()
	}
}

// TestRunPageGoneWhileAsked leaves while the page owes a challenge's answers: the page
// stops reading inside the challenge, sends answers that wait for the login, and goes;
// Run returns at once, with 1006.
func TestRunPageGoneWhileAsked(t *testing.T) {
	stalled := &stallConn{stalled: make(chan struct{}), closed: make(chan struct{})}
	r := startWith(t.Context(), t, testConfig(), interactiveDevice(t).listen(t), func(conn net.Conn) net.Conn {
		stalled.Conn = conn
		return stalled
	})
	stalled.stall.Store(true)
	read := make(chan struct{})
	go func() {
		defer close(read)
		if _, _, err := r.page.Read(t.Context()); err == nil {
			t.Error("the page read the challenge")
		}
	}()
	r.send(t, connectFrame(""))
	<-stalled.stalled
	r.send(t, `{"type":"answers","answers":["answer01","answer02"]}`)
	waitSelect("session.(*session).dispatch(")
	if err := r.page.CloseNow(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of the page's end")
	}
	<-read
	if failed := r.logs.record(t, "session failed"); failed["close_code"] != float64(closeAbnormal) {
		t.Errorf("session failed = %v, want close_code 1006", failed)
	}
}

// TestSessionDispatchAfterTheEnd dispatches frames once the session ended, as the end
// can come while the reader acts on one: answers no one waits for are dropped, and the
// write of input ends the SSH connection with ErrTargetLost by the end's cause.
func TestSessionDispatchAfterTheEnd(t *testing.T) {
	shell, stop := forwardSession(t, discardInput)
	defer stop()
	bridge, page := wsPair(t.Context(), t, plain)
	s, sctx, release := newSession(t.Context(), bridge, testConfig(), "192.0.2.10:22", testClient, "",
		discardLogger())
	s.client, s.shell = shell.client, shell.shell
	s.connected = true
	s.active.Store(true)
	s.pending.Store(uint32(protocol.KindAnswers))
	s.cancel(errStopped)
	if err := s.dispatch(sctx, websocket.MessageText, []byte(`{"type":"answers","answers":[]}`)); err != nil {
		t.Errorf("dispatch answers: %v", err)
	}
	err := s.dispatch(sctx, websocket.MessageBinary, []byte("ls\r"))
	if !errors.Is(err, sshclient.ErrTargetLost) || !errors.Is(err, errStopped) {
		t.Errorf("dispatch input = %v, want ErrTargetLost by errStopped", err)
	}
	release()
	if err := errors.Join(page.CloseNow(), bridge.CloseNow()); err != nil {
		t.Log(err)
	}
}

// base64Std returns the standard base64 of b.
func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// newAgent returns a keyring holding key and the SSH blob of its public key.
func newAgent(t *testing.T, key any) (keyring agent.ExtendedAgent, blob []byte) {
	t.Helper()
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("the keyring is no ExtendedAgent")
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	blob = signer.PublicKey().Marshal()
	return keyring, blob
}
