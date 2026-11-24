package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"syscall"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/internal/server"
)

// version is the release the build stamps with -ldflags "-X main.version=<release>".
var version = "dev"

// keyError is the key of the error a record carries.
const keyError = "error"

// The exit statuses of the process.
const (
	// exitClean ends a stop on a signal, the usage, the version and a probe that connects.
	exitClean = 0
	// exitFailure ends a failure at run time and a probe that does not connect.
	exitFailure = 1
	// exitInvalid ends a configuration or a command line to fix.
	exitInvalid = 2
)

// The routes the start record names: the pinned target's and the path's.
const (
	routePinned = "/ws"
	routePath   = "/ws/{host}/{port}"
)

// main runs the command line under a context the first SIGINT or SIGTERM cancels and
// exits with its status.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	status := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}

// run runs the command line args under ctx and returns the exit status. The usage and
// a refused configuration go to stderr, the version and the records to stdout.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var usage bytes.Buffer
	cfg, err := config.Load(args, &usage)
	if cfg == nil {
		switch {
		case errors.Is(err, config.ErrHelp):
			return writeOutput(stderr, usage.Bytes(), exitClean)
		case errors.Is(err, config.ErrVersionRequested):
			return writeOutput(stdout, []byte(version+" (go="+runtime.Version()+")\n"), exitClean)
		case errors.Is(err, config.ErrInvalidConfig):
			newLogger(&usage, slog.LevelError).LogAttrs(ctx, slog.LevelError, "invalid configuration",
				slog.Any(keyError, err))
		}
		return writeOutput(stderr, usage.Bytes(), exitInvalid)
	}
	log := newLogger(stdout, levelOf(&cfg.Server))
	if errors.Is(err, config.ErrHealthRequested) {
		return probe(ctx, log, cfg.Server.Address)
	}
	logStart(ctx, log, cfg)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Server.Address)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "listen failed", slog.String("address", cfg.Server.Address),
			slog.Any(keyError, err))
		return exitFailure
	}
	return stopped(ctx, log, server.New(cfg, log).Serve(ctx, ln))
}

// writeOutput writes p to w and returns status, or exitFailure when the write fails.
func writeOutput(w io.Writer, p []byte, status int) int {
	if _, err := w.Write(p); err != nil {
		return exitFailure
	}
	return status
}

// newLogger returns a logger that writes JSON records from level up to w.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// levelOf returns the lowest level of the records of s: debug with -server-debug,
// else info.
func levelOf(s *config.ServerConfig) slog.Level {
	if s.Debug {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// logStart logs the version, the listener, the route and the caps of cfg, then, at
// warn, each UWSB_ variable no setting reads.
func logStart(ctx context.Context, log *slog.Logger, cfg *config.Config) {
	route := []slog.Attr{slog.String("route", routePath)}
	caps := []slog.Attr{slog.Int("conn_max_total", cfg.Conn.MaxTotal),
		slog.Int("conn_max_per_host", cfg.Conn.MaxPerHost)}
	if cfg.SSH.Target != "" {
		route = []slog.Attr{slog.String("route", routePinned), slog.String("target", cfg.SSH.Target)}
		caps = caps[:1]
	}
	log.LogAttrs(ctx, slog.LevelInfo, "starting ubyte-webssh-bridge", slices.Concat(
		[]slog.Attr{slog.String("version", version), slog.String("address", cfg.Server.Address)}, route,
		[]slog.Attr{slog.String("certificate", cfg.Server.CertFile),
			slog.String("certificate_key", cfg.Server.KeyFile)}, caps)...)
	for _, name := range cfg.UnreadNames() {
		log.LogAttrs(ctx, slog.LevelWarn, "unread variable", slog.String("name", name))
	}
}

// stopped logs err, the end of the server, and returns the exit status: exitClean for
// nil, exitFailure for the rest.
func stopped(ctx context.Context, log *slog.Logger, err error) int {
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "serve failed", slog.Any(keyError, err))
		return exitFailure
	}
	return exitClean
}
