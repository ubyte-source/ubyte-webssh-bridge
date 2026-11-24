package main

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestProbeAddressReachesTheListener maps listen addresses to what the probe dials: an
// unspecified host the loopback of its family, any other host itself.
func TestProbeAddressReachesTheListener(t *testing.T) {
	for address, want := range map[string]string{
		":8443": "127.0.0.1:8443", "0.0.0.0:8443": "127.0.0.1:8443", "[::]:8443": "[::1]:8443",
		"127.0.0.1:8080": "127.0.0.1:8080", "[::1]:8443": "[::1]:8443", "192.0.2.10:8443": "192.0.2.10:8443",
	} {
		if got := probeAddress(address); got != want {
			t.Errorf("probeAddress(%q) = %q, want %q", address, got, want)
		}
	}
}

// TestProbeConnectsToAListener probes a listener the test opens: exitClean and no
// record.
func TestProbeConnectsToAListener(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer closeListener(t, ln)
	var out strings.Builder
	got := probe(t.Context(), newLogger(&out, slog.LevelInfo), ln.Addr().String())
	if got != exitClean || out.Len() != 0 {
		t.Errorf("probe() = %d, records %q, want %d and none", got, out.String(), exitClean)
	}
}

// TestProbeFailsWithoutAListener probes a port nothing listens on: exitFailure and the
// record naming the address.
func TestProbeFailsWithoutAListener(t *testing.T) {
	var out strings.Builder
	if got := probe(t.Context(), newLogger(&out, slog.LevelInfo), refusedAddress); got != exitFailure {
		t.Errorf("probe() = %d, want %d", got, exitFailure)
	}
	recs := recordsOf(out.String(), "health probe failed")
	if len(recs) != 1 || recs[0]["address"] != refusedAddress || recs[0]["level"] != "ERROR" ||
		recs[0]["error"] == nil {
		t.Errorf("records %q, want one at error with the address and the error", out.String())
	}
}

// TestProbeEndsWithTheContext probes a listener under a canceled context: the dial
// ends at once with the context, exitFailure.
func TestProbeEndsWithTheContext(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer closeListener(t, ln)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out strings.Builder
	if got := probe(ctx, newLogger(&out, slog.LevelInfo), ln.Addr().String()); got != exitFailure ||
		!strings.Contains(out.String(), "operation was canceled") {
		t.Errorf("probe(a canceled context) = %d, records %q, want %d and the cancel", got, out.String(), exitFailure)
	}
}

// silentAddress returns a loopback address whose listener takes no new connection: its
// backlog of 0 holds the one connection the test opens, so the kernel drops the SYN
// of the next.
func silentAddress(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket() = %v, want nil", err)
	}
	t.Cleanup(func() {
		if cerr := syscall.Close(fd); cerr != nil {
			t.Errorf("close the socket = %v, want nil", cerr)
		}
	})
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("Bind() = %v, want nil", err)
	}
	if err = syscall.Listen(fd, 0); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("Getsockname() = %v, want nil", err)
	}
	inet, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("Getsockname() = %T, want an IPv4 address", sa)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(inet.Port))
	var d net.Dialer
	held, err := d.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatalf("dial the backlog's connection = %v, want nil", err)
	}
	t.Cleanup(func() {
		if cerr := held.Close(); cerr != nil {
			t.Errorf("close the backlog's connection = %v, want nil", cerr)
		}
	})
	return address
}

// TestProbeGivesUpWithinFourSeconds probes a listener that never accepts: the probe
// gives up after its 4 s, exitFailure with the timeout.
func TestProbeGivesUpWithinFourSeconds(t *testing.T) {
	address := silentAddress(t)
	var out strings.Builder
	start := time.Now()
	status := make(chan int, 1)
	go func() { status <- probe(t.Context(), newLogger(&out, slog.LevelInfo), address) }()
	select {
	case got := <-status:
		if elapsed := time.Since(start); got != exitFailure || elapsed < 4*time.Second ||
			!strings.Contains(out.String(), "i/o timeout") {
			t.Errorf("probe(a silent listener) = %d after %v, records %q, want %d after 4s and the timeout", got,
				elapsed, out.String(), exitFailure)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("probe(a silent listener) still dials after 7s, want it given up after 4s")
	}
}
