// Package sshclient is the SSH leg of a session. Dial connects to the target within
// the connect timeout and logs in within the login timeout: it offers x/crypto's secure
// algorithms and then its insecure ones, accepts the host key of the first key
// exchange and pins it for the connection, so a rekey that presents another key ends
// it, and tries the page's public key through a signer that asks the Page for each
// signature, then keyboard-interactive, then the password, three tries each; the typed
// password stays reachable only until the handshake returns. A Client opens and starts
// a Shell on a PTY of terminal type xterm with UTF-8, still within the login timeout,
// whose input, size and exit the session drives. Every error wraps one sentinel of the
// package, for callers to branch on with errors.Is.
package sshclient
