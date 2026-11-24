package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/coder/websocket"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/session"
)

// The reasons a refused record gives.
const (
	refusedOrigin  = "origin"
	refusedTarget  = "target"
	refusedUpgrade = "upgrade"
	refusedRate    = "rate"
	refusedBusy    = "busy"
)

// keyError is the key of the error a record carries.
const keyError = "error"

// forwardedSpaces are what surrounds an entry of X-Forwarded-For and X-Real-IP.
const forwardedSpaces = " \t"

// serveSocket opens a session to the target resolve finds for r once the Origin, the
// target, the upgrade, the rate of the client and the caps let it, and runs it.
func (s *Server) serveSocket(w http.ResponseWriter, r *http.Request, resolve func(*http.Request) (string, error)) {
	ctx := r.Context()
	client, peer := clientAddress(r, s.cfg.Server.TrustedProxies)
	attrs := addressAttrs(client, peer)
	if r.Header.Get("Origin") == "" {
		s.refused(ctx, refusedOrigin, attrs)
		http.Error(w, "origin required", http.StatusForbidden)
		return
	}
	target, err := resolve(r)
	if err != nil {
		s.refused(ctx, refusedTarget, attrs)
		http.Error(w, config.ErrInvalidTarget.Error(), http.StatusBadRequest)
		return
	}
	attrs = append(attrs, slog.String("target", target))
	// Shutdown waits for a request until its handler hijacks the connection, so the
	// count holds every session before the stop waits for them.
	s.sessions.Add(1)
	defer s.sessions.Done()
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		s.refused(ctx, refusedUpgrade, append(attrs, slog.Any(keyError, err)))
		return
	}
	if !s.rate.admit(rateKey(client)) {
		s.refuse(ctx, conn, protocol.CloseRateLimited, refusedRate, attrs)
		return
	}
	if !s.caps.admit(target) {
		s.refuse(ctx, conn, protocol.CloseBusy, refusedBusy, attrs)
		return
	}
	defer s.caps.release(target)
	peerText := ""
	if peer != client {
		peerText = peer.String()
	}
	session.Run(ctx, conn, s.cfg, target, client.String(), peerText, s.log)
}

// addressAttrs returns the attributes of client and, when it differs, of peer.
func addressAttrs(client, peer netip.Addr) []slog.Attr {
	attrs := []slog.Attr{slog.String("client", client.String())}
	if peer != client {
		attrs = append(attrs, slog.String("peer", peer.String()))
	}
	return attrs
}

// refuse closes conn with code and its reason and logs the refusal, with the failure
// of the close when there is one.
func (s *Server) refuse(ctx context.Context, conn *websocket.Conn, code protocol.CloseCode, reason string,
	attrs []slog.Attr) {
	if err := conn.Close(websocket.StatusCode(code), code.Reason()); err != nil {
		attrs = append(attrs, slog.Any(keyError, err))
	}
	s.refused(ctx, reason, attrs)
}

// refused logs at debug a request refused for reason.
func (s *Server) refused(ctx context.Context, reason string, attrs []slog.Attr) {
	s.log.LogAttrs(ctx, slog.LevelDebug, "refused", slices.Concat([]slog.Attr{slog.String("reason", reason)},
		attrs)...)
}

// clientAddress returns the client of r and its TCP peer, unmapped: the peer itself
// unless trusted names it a proxy, whose X-Forwarded-For is walked from the right
// through trusted addresses, or without one whose X-Real-IP names the client.
func clientAddress(r *http.Request, trusted []netip.Prefix) (client, peer netip.Addr) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, netip.Addr{}
	}
	peer = ap.Addr().Unmap()
	if !trusts(trusted, peer) {
		return peer, peer
	}
	lines := r.Header.Values("X-Forwarded-For")
	if len(lines) == 0 {
		return realIP(r, peer), peer
	}
	entries := strings.Split(strings.Join(lines, ","), ",")
	client = peer
	for _, entry := range slices.Backward(entries) {
		addr, err := netip.ParseAddr(strings.Trim(entry, forwardedSpaces))
		if err != nil || addr.Zone() != "" {
			break
		}
		client = addr.Unmap()
		if !trusts(trusted, client) {
			break
		}
	}
	return client, peer
}

// realIP returns the address X-Real-IP of r names, unmapped, or peer when it names
// none.
func realIP(r *http.Request, peer netip.Addr) netip.Addr {
	addr, err := netip.ParseAddr(strings.Trim(r.Header.Get("X-Real-IP"), forwardedSpaces))
	if err != nil || addr.Zone() != "" {
		return peer
	}
	return addr.Unmap()
}

// trusts reports whether a prefix of trusted holds addr.
func trusts(trusted []netip.Prefix, addr netip.Addr) bool {
	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}
