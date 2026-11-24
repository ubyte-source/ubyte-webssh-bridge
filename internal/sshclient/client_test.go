package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// rsaBlob returns the SSH wire blob of an RSA public key whose modulus has bits bits;
// the modulus need not be a product of primes for the blob to parse.
func rsaBlob(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Or(n, big.NewInt(1))
	return ssh.Marshal(rsaKey{Type: ssh.KeyAlgoRSA, E: big.NewInt(65537), N: n})
}

// acceptKey makes d accept user01 with the key of blob.
func (d *device) acceptKey(blob []byte) {
	d.config.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == testUser && slices.Equal(key.Marshal(), blob) {
			return &ssh.Permissions{}, nil
		}
		return nil, errRefusedByDevice
	}
}

func TestParseKeyAccepts(t *testing.T) {
	for _, kind := range []string{"ed25519", "p256", "p384", "p521", "rsa"} {
		if _, err := parseKey(publicBlob(t, newKey(t, kind))); err != nil {
			t.Errorf("parseKey(%s): %v", kind, err)
		}
	}
	for _, bits := range []int{1024, 16384} {
		if _, err := parseKey(rsaBlob(bits)); err != nil {
			t.Errorf("parseKey(RSA %d): %v", bits, err)
		}
	}
}

func TestParseKeyRefuses(t *testing.T) {
	dsa := ssh.Marshal(struct {
		Type       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", big.NewInt(23), big.NewInt(11), big.NewInt(2), big.NewInt(4)})
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	security := ssh.Marshal(struct {
		Type        string
		Key         []byte
		Application string
	}{"sk-ssh-ed25519@openssh.com", edKey[ed25519.SeedSize:], "ssh:"})
	cases := []struct {
		name string
		blob []byte
	}{
		{"a DSA blob", dsa},
		{"an RSA 768 key", rsaBlob(768)},
		{"an RSA 1023 key", rsaBlob(1023)},
		{"an RSA 16385 key", rsaBlob(16385)},
		{"a security key", security},
		{"garbage", []byte("user01")},
		{"an empty blob", []byte{}},
	}
	for _, c := range cases {
		if _, err := parseKey(c.blob); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("parseKey(%s) error = %v, want ErrInvalidKey", c.name, err)
		}
	}
}

// TestParseKeyWrapsTheParseError refuses a blob x/crypto cannot parse: the refusal
// wraps x/crypto's error.
func TestParseKeyWrapsTheParseError(t *testing.T) {
	blob := []byte("user01")
	_, parseErr := ssh.ParsePublicKey(blob)
	if _, err := parseKey(blob); parseErr == nil || !errors.Is(err, ErrInvalidKey) || !errors.Is(err, parseErr) {
		t.Errorf("parseKey error = %v, want ErrInvalidKey wrapping %v", err, parseErr)
	}
}

func TestDialInvalidKeyBeforeDial(t *testing.T) {
	login := protocol.Login{User: testUser, Key: []byte("user01")}
	_, err := Dial(t.Context(), sshConfig(), "127.0.0.1:1", login, newTestPage(t, nil))
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Dial error = %v, want ErrInvalidKey", err)
	}
}

func TestDialPassword(t *testing.T) {
	d := newDevice(t)
	d.run = d.exitWith(0)
	target := d.listen(t)
	c, err := Dial(t.Context(), sshConfig(), target, *passwordLogin(), newTestPage(t, nil))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if got := c.Method(); got != methodPassword {
		t.Errorf("Method() = %q, want %q", got, methodPassword)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// refusedAddress refuses every connection: port 1 is privileged, and no test binds it.
const refusedAddress = "127.0.0.1:1"

func TestDialUnreachable(t *testing.T) {
	_, err := Dial(t.Context(), sshConfig(), refusedAddress, *passwordLogin(), newTestPage(t, nil))
	var refused *net.OpError
	if !errors.Is(err, ErrUnreachable) || !errors.As(err, &refused) {
		t.Fatalf("Dial error = %v, want ErrUnreachable wrapping the dial's error", err)
	}
}

// TestDialCanceledContext dials a listening device under a context that ended: Dial
// returns the cause and connects nothing.
func TestDialCanceledContext(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatal("the listener is no TCPListener")
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errPageGone)
	_, err = Dial(ctx, sshConfig(), ln.Addr().String(), *passwordLogin(), newTestPage(t, nil))
	if !errors.Is(err, errPageGone) {
		t.Errorf("Dial error = %v, want the cause", err)
	}
	if err := listener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Accept = %v, %v, want no connection", conn, err)
	}
	if err := ln.Close(); err != nil {
		t.Errorf("listener: %v", err)
	}
}

// TestDialEndedDuringLogin ends ctx while the page signs: the login ends with the cause
// at once, before the login timeout.
func TestDialEndedDuringLogin(t *testing.T) {
	d := newDevice(t)
	key := newKey(t, "ed25519")
	login := protocol.Login{User: testUser, Key: publicBlob(t, key)}
	d.acceptKey(login.Key)
	target := d.listen(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	page := newTestPage(t, key)
	page.sign = func(context.Context, []byte, uint32) ([]byte, error) {
		cancel(errPageGone)
		return nil, errPageGone
	}
	cfg := sshConfig()
	cfg.LoginTimeout = time.Second
	_, err := Dial(ctx, cfg, target, login, page)
	if !errors.Is(err, errPageGone) || errors.Is(err, ErrLoginTimeout) {
		t.Fatalf("Dial error = %v, want the cause", err)
	}
}

func TestDialClosedAfterVersion(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_, acceptErr = conn.Write([]byte("SSH-2.0-device\r\n"))
			acceptErr = errors.Join(acceptErr, conn.Close())
		}
		served <- acceptErr
	}()
	_, err = Dial(t.Context(), sshConfig(), ln.Addr().String(), *passwordLogin(), newTestPage(t, nil))
	if !errors.Is(err, ErrHandshake) {
		t.Errorf("Dial error = %v, want ErrHandshake", err)
	}
	if closeErr := errors.Join(<-served, ln.Close()); closeErr != nil {
		t.Errorf("device: %v", closeErr)
	}
}

// TestLogInSilentDevice logs in to a device that never sends its version: the login
// timeout closes the connection and ends the login.
func TestLogInSilentDevice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, _ := pipe()
		start := time.Now()
		_, err := logIn(t.Context(), client, sshConfig().LoginTimeout, testTarget, passwordLogin(), nil,
			newTestPage(t, nil))
		if !errors.Is(err, ErrLoginTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("logIn error = %v, want ErrLoginTimeout wrapping the deadline", err)
		}
		if got := time.Since(start); got != sshConfig().LoginTimeout {
			t.Errorf("logIn took %v, want %v", got, sshConfig().LoginTimeout)
		}
	})
}

func TestLogInNoCommonAlgorithm(t *testing.T) {
	d := newDevice(t)
	d.config.Ciphers = []string{"aes256-cbc-unknown"}
	_, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("logIn error = %v, want ErrHandshake", err)
	}
}

func TestLogInInsecureAlgorithms(t *testing.T) {
	cases := []struct {
		name string
		set  func(c *ssh.ServerConfig)
	}{
		{"diffie-hellman-group1-sha1", func(c *ssh.ServerConfig) {
			c.KeyExchanges = []string{"diffie-hellman-group1-sha1"}
		}},
		{"diffie-hellman-group14-sha1", func(c *ssh.ServerConfig) {
			c.KeyExchanges = []string{"diffie-hellman-group14-sha1"}
		}},
		{"diffie-hellman-group-exchange-sha1", func(c *ssh.ServerConfig) {
			c.KeyExchanges = []string{"diffie-hellman-group-exchange-sha1"}
		}},
		{"3des-cbc", func(c *ssh.ServerConfig) { c.Ciphers = []string{"3des-cbc"} }},
		{"aes128-cbc", func(c *ssh.ServerConfig) { c.Ciphers = []string{"aes128-cbc"} }},
		{"arcfour", func(c *ssh.ServerConfig) { c.Ciphers = []string{"arcfour"} }},
		{"hmac-sha1-96", func(c *ssh.ServerConfig) {
			c.Ciphers, c.MACs = []string{"aes128-ctr"}, []string{"hmac-sha1-96"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t)
			c.set(d.config)
			client, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
			if err != nil {
				t.Fatalf("logIn: %v", err)
			}
			if got := client.Method(); got != methodPassword {
				t.Errorf("Method() = %q, want %q", got, methodPassword)
			}
		})
	}
}

func TestLogInSSHRSAHostKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the RSA signer takes no algorithm")
	}
	only, err := ssh.NewSignerWithAlgorithms(algorithmSigner, []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	d := newDevice(t)
	d.config = &ssh.ServerConfig{PasswordCallback: d.config.PasswordCallback}
	d.config.AddHostKey(only)
	page := newTestPage(t, nil)
	if _, err := logInPipe(t, d, passwordLogin(), page); err != nil {
		t.Fatalf("logIn: %v", err)
	}
	if want := []string{"ssh-rsa " + ssh.FingerprintSHA256(signer.PublicKey())}; !slices.Equal(page.hostKeys, want) {
		t.Errorf("host keys = %q, want %q", page.hostKeys, want)
	}
}

func TestLogInHostKeyReportedOnce(t *testing.T) {
	d := newDevice(t)
	host := newHostKey(t)
	d.config.AddHostKey(host)
	d.config.RekeyThreshold = 256
	d.run = func(ch ssh.Channel) {
		_, err := ch.Write([]byte(strings.Repeat("output of the device ", 100)))
		d.note(err)
		d.exitWith(0)(ch)
	}
	page := newTestPage(t, nil)
	c, err := logInPipe(t, d, passwordLogin(), page)
	if err != nil {
		t.Fatalf("logIn: %v", err)
	}
	shell, err := c.Open(t.Context(), protocol.Size{Cols: 80, Rows: 24}, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if exit, err := shell.Wait(); err != nil || exit != (protocol.Exit{HasStatus: true}) {
		t.Fatalf("Wait = %+v, %v", exit, err)
	}
	want := []string{"ssh-ed25519 " + ssh.FingerprintSHA256(host.PublicKey())}
	if !slices.Equal(page.hostKeys, want) {
		t.Errorf("host keys = %q, want %q", page.hostKeys, want)
	}
}

func TestLogInCertificateHostKey(t *testing.T) {
	authority, host := newHostKey(t), newHostKey(t)
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"192.0.2.10"},
		ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	d := newDevice(t)
	d.config = &ssh.ServerConfig{PasswordCallback: d.config.PasswordCallback}
	d.config.AddHostKey(certSigner)
	page := newTestPage(t, nil)
	if _, err := logInPipe(t, d, passwordLogin(), page); err != nil {
		t.Fatalf("logIn: %v", err)
	}
	want := []string{"ssh-ed25519 " + ssh.FingerprintSHA256(host.PublicKey())}
	if !slices.Equal(page.hostKeys, want) {
		t.Errorf("host keys = %q, want %q", page.hostKeys, want)
	}
}

func TestLogInHostKeyChangedDuringLogin(t *testing.T) {
	d := newDevice(t)
	d.config = &ssh.ServerConfig{PasswordCallback: d.config.PasswordCallback}
	d.config.AddHostKey(newSwitchingKey(t, 1))
	d.config.RekeyThreshold = 256
	d.config.BannerCallback = func(ssh.ConnMetadata) string { return strings.Repeat("Authorized use only. ", 50) }
	page := newTestPage(t, nil, []string{"wrong"}, []string{"wrong"}, []string{"wrong"})
	_, err := logInPipe(t, d, &protocol.Login{User: testUser}, page)
	if !errors.Is(err, ErrTargetLost) {
		t.Fatalf("logIn error = %v, want ErrTargetLost", err)
	}
}

func TestHostKeysCheck(t *testing.T) {
	page := newTestPage(t, nil)
	keys := &hostKeys{page: page}
	first, second := newHostKey(t).PublicKey(), newHostKey(t).PublicKey()
	if err := keys.check("", nil, first); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if err := keys.check("", nil, first); err != nil {
		t.Fatalf("same key: %v", err)
	}
	if err := keys.check("", nil, second); !errors.Is(err, errHostKeyChanged) || !keys.changed.Load() {
		t.Fatalf("another key: %v, want errHostKeyChanged", err)
	}
	if len(page.hostKeys) != 1 {
		t.Errorf("host keys = %q, want one", page.hostKeys)
	}
}

func TestLogInZeroesPassword(t *testing.T) {
	for _, password := range []string{testPassword, "wrong"} {
		d := newDevice(t)
		login := &protocol.Login{User: testUser, Password: secret.New(password)}
		_, err := logInPipe(t, d, login, newTestPage(t, nil, []string{"wrong"}, []string{"wrong"},
			[]string{"wrong"}, []string{"wrong"}, []string{"wrong"}))
		if (err == nil) != (password == testPassword) || (err != nil && !errors.Is(err, ErrAuthFailed)) {
			t.Fatalf("logIn with %q: %v", password, err)
		}
		if !login.Password.IsZero() {
			t.Errorf("logIn with %q kept the password", password)
		}
	}
}

func TestLogInTimeout(t *testing.T) {
	cases := []struct {
		name string
		set  func(d *device, login *protocol.Login, page *testPage)
	}{
		{"a sign request never answered", func(d *device, login *protocol.Login, page *testPage) {
			key := newKey(t, "ed25519")
			login.Key = publicBlob(t, key)
			d.acceptKey(login.Key)
			page.sign = func(ctx context.Context, _ []byte, _ uint32) ([]byte, error) {
				<-ctx.Done()
				return nil, context.Cause(ctx)
			}
		}},
		{"a challenge never answered", func(_ *device, _ *protocol.Login, _ *testPage) {}},
		{"a keyboard-interactive round never answered", func(d *device, _ *protocol.Login, _ *testPage) {
			d.interactive(prompt("Code: ", true, "123456"))
		}},
		{"a banner never shown", func(d *device, _ *protocol.Login, page *testPage) {
			d.config.BannerCallback = func(ssh.ConnMetadata) string { return "Authorized use only.\r\n" }
			page.bannerWaits = true
		}},
		{"a notice never shown", func(d *device, _ *protocol.Login, page *testPage) {
			d.interactive(round{name: "Notice"}, prompt("Code: ", true, "123456"))
			page.bannerWaits = true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newDevice(t)
				login := &protocol.Login{User: testUser}
				page := newTestPage(t, nil)
				c.set(d, login, page)
				start := time.Now()
				_, err := logInPipe(t, d, login, page)
				if !errors.Is(err, ErrLoginTimeout) {
					t.Fatalf("logIn error = %v, want ErrLoginTimeout", err)
				}
				if got := time.Since(start); got != sshConfig().LoginTimeout {
					t.Errorf("logIn took %v, want %v", got, sshConfig().LoginTimeout)
				}
			})
		})
	}
}

func TestLogInCanceledContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newDevice(t)
		ctx, cancel := context.WithCancelCause(t.Context())
		page := newTestPage(t, nil)
		page.sign = func(context.Context, []byte, uint32) ([]byte, error) {
			cancel(errPageGone)
			return nil, errPageGone
		}
		key := newKey(t, "ed25519")
		login := &protocol.Login{User: testUser, Key: publicBlob(t, key)}
		d.acceptKey(login.Key)
		parsed, err := parseKey(login.Key)
		if err != nil {
			t.Fatal(err)
		}
		client, server := pipe()
		d.serve(server)
		start := time.Now()
		_, err = logIn(ctx, client, sshConfig().LoginTimeout, testTarget, login, parsed, page)
		if !errors.Is(err, errPageGone) || errors.Is(err, ErrLoginTimeout) || time.Since(start) != 0 {
			t.Errorf("logIn error = %v after %v, want the cause at once", err, time.Since(start))
		}
		d.stop()
	})
}

func TestClientOpenRefused(t *testing.T) {
	for _, refused := range []string{"session", "pty-req", "shell"} {
		d := newDevice(t)
		d.refuse = []string{refused}
		c, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
		if err != nil {
			t.Fatalf("logIn: %v", err)
		}
		_, err = c.Open(t.Context(), protocol.Size{Cols: 80, Rows: 24}, io.Discard)
		var rejected *ssh.OpenChannelError
		if !errors.Is(err, ErrShellRefused) || errors.As(err, &rejected) != (refused == "session") {
			t.Errorf("Open with %s refused: error = %v, want ErrShellRefused wrapping the refusal", refused, err)
		}
	}
}

// TestClientOpenTimesOut opens the shell of a device that never answers the PTY or the
// shell request: the login's deadline, counted from the start of the login, ends it.
func TestClientOpenTimesOut(t *testing.T) {
	for _, ignored := range []string{"pty-req", "shell"} {
		t.Run(ignored, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newDevice(t)
				d.ignore = []string{ignored}
				start := time.Now()
				c, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
				if err != nil {
					t.Fatalf("logIn: %v", err)
				}
				time.Sleep(time.Minute)
				_, err = c.Open(t.Context(), protocol.Size{Cols: 80, Rows: 24}, io.Discard)
				if !errors.Is(err, ErrLoginTimeout) || !errors.Is(err, io.EOF) {
					t.Errorf("Open error = %v, want ErrLoginTimeout wrapping the request's end", err)
				}
				if got := time.Since(start); got != sshConfig().LoginTimeout {
					t.Errorf("Open returned %v after the login began, want %v", got, sshConfig().LoginTimeout)
				}
			})
		})
	}
}

// TestClientOpenEndedByContext ends ctx while the device keeps the PTY request
// unanswered: Open returns the cause at once.
func TestClientOpenEndedByContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newDevice(t)
		d.ignore = []string{"pty-req"}
		c, err := logInPipe(t, d, passwordLogin(), newTestPage(t, nil))
		if err != nil {
			t.Fatalf("logIn: %v", err)
		}
		ctx, cancel := context.WithCancelCause(t.Context())
		time.AfterFunc(time.Second, func() { cancel(errPageGone) })
		start := time.Now()
		_, err = c.Open(ctx, protocol.Size{Cols: 80, Rows: 24}, io.Discard)
		if !errors.Is(err, errPageGone) || errors.Is(err, ErrShellRefused) || errors.Is(err, ErrLoginTimeout) {
			t.Errorf("Open error = %v, want the cause", err)
		}
		if got := time.Since(start); got != time.Second {
			t.Errorf("Open returned after %v, want 1s", got)
		}
	})
}

// TestCause classes the end of a login in order: the end of ctx, the login timeout, a
// host key that changed, a handshake that never reached the host key, else the step's.
func TestCause(t *testing.T) {
	ended, cancel := context.WithCancelCause(t.Context())
	cancel(errPageGone)
	contextOf := func(isEnded bool) context.Context {
		if isEnded {
			return ended
		}
		return t.Context()
	}
	cases := []struct {
		name                string
		want                error
		ctxEnded, lctxEnded bool
		keySeen, keyChanged bool
	}{
		{"ctx ended", errPageGone, true, true, true, true},
		{"login timed out", ErrLoginTimeout, false, true, true, true},
		{"host key changed", ErrTargetLost, false, false, true, true},
		{"no host key", ErrHandshake, false, false, false, false},
		{"step failed", ErrShellRefused, false, false, true, false},
	}
	for _, c := range cases {
		keys := &hostKeys{}
		keys.seen.Store(c.keySeen)
		keys.changed.Store(c.keyChanged)
		got := cause(contextOf(c.ctxEnded), contextOf(c.lctxEnded), keys, ErrShellRefused)
		if !errors.Is(got, c.want) {
			t.Errorf("cause(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClientOpenRequestsXterm(t *testing.T) {
	d := newDevice(t)
	d.run = d.exitWith(0)
	openShell(t, d)
	var pty struct {
		Term             string
		Cols, Rows, W, H uint32
		Modes            string
	}
	if err := ssh.Unmarshal(d.waitFor("pty-req"), &pty); err != nil {
		t.Fatal(err)
	}
	if pty.Term != "xterm" || pty.Cols != 80 || pty.Rows != 24 {
		t.Errorf("pty-req = %+v, want xterm 80x24", pty)
	}
}

func TestClientClose(t *testing.T) {
	d := newDevice(t)
	target := d.listen(t)
	c, err := Dial(t.Context(), sshConfig(), target, *passwordLogin(), newTestPage(t, nil))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	for range 2 {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}

// TestWatchedConnRead reads up to the end of the connection: the device's close and its
// reset are no failure, a TCP keep-alive that timed out is.
func TestWatchedConnRead(t *testing.T) {
	for _, c := range []struct {
		end    error
		failed bool
	}{{io.EOF, false}, {readError(syscall.ECONNRESET), false}, {readError(syscall.ETIMEDOUT), true}} {
		client, server := pipe()
		w := &watchedConn{Conn: client}
		if _, err := server.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Read(make([]byte, 1)); err != nil || w.failed.Load() {
			t.Fatalf("Read = %v, failed %t", err, w.failed.Load())
		}
		if err := server.end.close(c.end); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Read(make([]byte, 1)); !errors.Is(err, c.end) || w.failed.Load() != c.failed {
			t.Errorf("Read after %v = %v, failed %t, want %t", c.end, err, w.failed.Load(), c.failed)
		}
	}
}
