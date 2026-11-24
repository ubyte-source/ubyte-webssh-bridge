package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
)

// The bounds of a connection beside the handshake timeout: a file response, an idle
// connection, and the request line and headers, past which net/http reads 4096 bytes.
const (
	writeTimeout   = 60 * time.Second
	idleTimeout    = 120 * time.Second
	maxHeaderBytes = 16384
)

// Server serves the page and the WebSocket of cfg; its zero value is not ready: New
// builds it.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	caps     *caps
	rate     *limiter
	handler  http.Handler
	sessions sync.WaitGroup
}

// New returns the Server of cfg, which writes its records to log.
func New(cfg *config.Config, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, log: log, caps: newCaps(&cfg.Conn, cfg.SSH.Target != ""), rate: newLimiter(&cfg.Rate)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", serveFile)
	if cfg.SSH.Target != "" {
		mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
			s.serveSocket(w, r, func(*http.Request) (string, error) { return cfg.SSH.Target, nil })
		})
	} else {
		mux.HandleFunc("GET /ws/{host}/{port}", func(w http.ResponseWriter, r *http.Request) {
			s.serveSocket(w, r, pathTarget)
		})
	}
	s.handler = withPolicy(mux)
	return s
}

// pathTarget returns the target the path of r names.
func pathTarget(r *http.Request) (string, error) {
	target, err := config.JoinTarget(r.PathValue("host"), r.PathValue("port"))
	if err != nil {
		return "", fmt.Errorf("path target: %w", err)
	}
	return target, nil
}

// Serve serves on ln until ctx ends, then stops within the shutdown budget; nil after
// a stop by ctx.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	life, end := context.WithCancel(ctx)
	defer end()
	srv := s.httpServer(life)
	s.log.LogAttrs(ctx, slog.LevelInfo, "serving", slog.String("address", ln.Addr().String()))
	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-served:
		s.stop(ctx, srv, end)
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	s.log.LogAttrs(ctx, slog.LevelInfo, "stopping", slog.Any("cause", context.Cause(ctx)))
	s.stop(ctx, srv, end)
	return nil
}

// httpServer returns the HTTP server of s, whose requests derive from life: TLS 1.2
// or higher with the pair of the configuration, and the bounds of each connection.
func (s *Server) httpServer(life context.Context) *http.Server {
	return &http.Server{
		Handler: s.handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{s.cfg.Server.Certificate},
		},
		ReadHeaderTimeout: s.cfg.WS.HandshakeTimeout,
		ReadTimeout:       s.cfg.WS.HandshakeTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		BaseContext:       func(net.Listener) context.Context { return life },
	}
}

// stop ends the sessions through end, the lifetime context's cancel, closes the
// listener and the idle connections, and waits for the sessions within the shutdown
// budget, past which it closes every connection and logs at error.
func (s *Server) stop(ctx context.Context, srv *http.Server, end context.CancelFunc) {
	end()
	budget := s.cfg.Server.ShutdownTimeout
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()
	err := srv.Shutdown(stopCtx)
	if err == nil {
		err = s.drain(stopCtx)
	}
	if err == nil {
		return
	}
	s.log.LogAttrs(ctx, slog.LevelError, "stop outlasted the budget", slog.Duration("timeout", budget),
		slog.Any(keyError, errors.Join(err, srv.Close())))
}

// drain waits for the sessions until ctx ends, then returns its error.
func (s *Server) drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.sessions.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for the sessions: %w", ctx.Err())
	}
}
