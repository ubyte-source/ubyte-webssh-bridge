package protocol

// CloseCode is a code the bridge closes a WebSocket with.
type CloseCode uint16

// The close codes of the bridge: three of the WebSocket protocol, then the bridge's
// own, one per way a session ends.
const (
	CloseNormal          CloseCode = 1000
	CloseGoingAway       CloseCode = 1001
	CloseViolation       CloseCode = 1008
	CloseAuthFailed      CloseCode = 4002
	CloseUnreachable     CloseCode = 4003
	CloseHandshakeFailed CloseCode = 4004
	CloseLoginTimeout    CloseCode = 4005
	CloseShellRefused    CloseCode = 4006
	CloseBusy            CloseCode = 4007
	CloseRateLimited     CloseCode = 4008
	ClosePageSilent      CloseCode = 4009
	CloseTargetLost      CloseCode = 4010
)

// Reason returns the fixed text the bridge sends with c, or "" for a code it does not
// send.
func (c CloseCode) Reason() string {
	reasons := [...]struct {
		text string
		code CloseCode
	}{
		{"session ended", CloseNormal},
		{"server shutting down", CloseGoingAway},
		{"protocol violation", CloseViolation},
		{"authentication failed", CloseAuthFailed},
		{"target unreachable", CloseUnreachable},
		{"SSH handshake failed", CloseHandshakeFailed},
		{"login timed out", CloseLoginTimeout},
		{"shell refused", CloseShellRefused},
		{"too many sessions", CloseBusy},
		{"too many new sessions, retry later", CloseRateLimited},
		{"page stopped answering", ClosePageSilent},
		{"connection to the target lost", CloseTargetLost},
	}
	for _, r := range reasons {
		if r.code == c {
			return r.text
		}
	}
	return ""
}
