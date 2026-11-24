package main

import (
	"encoding/json/v2"
	"net"
	"os"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

// runMainEnv is the variable that makes the test binary a child that runs main in
// place of the tests.
const runMainEnv = "CMD_UBYTE_WEBSSH_BRIDGE_RUN_MAIN"

// TestMain runs main in a child, else the tests, failing on any goroutine they leave
// running.
func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) != "" {
		main()
	}
	goleak.VerifyTestMain(m)
}

// recordsOf returns the JSON records of text whose message is msg, each decoded into a
// map; a line that is not a JSON object is skipped.
func recordsOf(text, msg string) []map[string]any {
	var out []map[string]any
	for line := range strings.Lines(text) {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// refusedAddress refuses every connection: port 1 is privileged, and no test binds it.
const refusedAddress = "127.0.0.1:1"

func closeListener(t *testing.T, ln net.Listener) {
	t.Helper()
	if err := ln.Close(); err != nil {
		t.Errorf("close the listener = %v, want nil", err)
	}
}
