// Package server is the HTTPS server of the bridge: TLS 1.2 or higher with the
// configured pair, the embedded page under one Content-Security-Policy, and the
// WebSocket of a session, on /ws to the pinned target or on /ws/{host}/{port} to the
// target of the path. The client is the TCP peer, or, behind a trusted proxy, the
// address its X-Forwarded-For or X-Real-IP names. Before a session runs, the WebSocket
// handler checks the Origin, the target, the rate of new sessions of the client
// address and the caps on concurrent sessions, without a lock on the way. When the
// context of Serve ends, every session closes and Serve waits for them within the
// shutdown budget.
package server
