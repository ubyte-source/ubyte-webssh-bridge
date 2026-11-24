package main

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"
)

// healthTimeout bounds the probe's dial, under the image's HEALTHCHECK timeout of 5 s.
const healthTimeout = 4 * time.Second

// probe dials the listen address over TCP within healthTimeout and returns exitClean
// once it accepts, else exitFailure, logged.
func probe(ctx context.Context, log *slog.Logger, address string) int {
	target := probeAddress(address)
	conn, err := (&net.Dialer{Timeout: healthTimeout}).DialContext(ctx, "tcp", target)
	if err == nil {
		err = conn.Close()
	}
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "health probe failed", slog.String("address", target),
			slog.Any(keyError, err))
		return exitFailure
	}
	return exitClean
}

// probeAddress returns the address that reaches the listener of address: the loopback
// of its family for an unspecified host, the host itself otherwise.
func probeAddress(address string) string {
	i := strings.LastIndexByte(address, ':')
	host, port := strings.Trim(address[:i], "[]"), address[i+1:]
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}
