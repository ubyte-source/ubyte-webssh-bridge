package sshclient

import (
	"strings"
	"testing"
)

func TestErrHostKeyChangedAndSentinelTexts(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrUnreachable, "sshclient: target unreachable"},
		{ErrHandshake, "sshclient: SSH handshake failed"},
		{ErrAuthFailed, "sshclient: authentication failed"},
		{ErrLoginTimeout, "sshclient: login timed out"},
		{ErrShellRefused, "sshclient: shell refused"},
		{ErrTargetLost, "sshclient: connection to the target lost"},
		{ErrInvalidKey, "sshclient: invalid public key"},
		{errHostKeyChanged, "sshclient: host key changed"},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.want || !strings.HasPrefix(got, errPrefix) {
			t.Errorf("error text = %q, want %q", got, c.want)
		}
	}
}
