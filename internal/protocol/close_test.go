package protocol

import "testing"

func TestCloseCodeReason(t *testing.T) {
	cases := []struct {
		want string
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
		{"", 1005},
		{"", 1009},
	}
	for _, c := range cases {
		if got := c.code.Reason(); got != c.want {
			t.Errorf("CloseCode(%d).Reason() = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestCloseCodeValues(t *testing.T) {
	cases := []struct {
		code CloseCode
		want uint16
	}{
		{CloseNormal, 1000}, {CloseGoingAway, 1001}, {CloseViolation, 1008},
		{CloseAuthFailed, 4002}, {CloseUnreachable, 4003}, {CloseHandshakeFailed, 4004},
		{CloseLoginTimeout, 4005}, {CloseShellRefused, 4006}, {CloseBusy, 4007},
		{CloseRateLimited, 4008}, {ClosePageSilent, 4009}, {CloseTargetLost, 4010},
	}
	for _, c := range cases {
		if uint16(c.code) != c.want {
			t.Errorf("close code %d, want %d", c.code, c.want)
		}
	}
}
