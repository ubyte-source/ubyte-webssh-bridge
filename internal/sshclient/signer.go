package sshclient

import (
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// errBadSignature reports a signature of the page that is not the SSH wire signature
// of the asked algorithm over the data by the announced key.
var errBadSignature = errors.New(errPrefix + "bad signature from the page")

// pageSigner signs with the page's key: the page holds the private key, and sign asks
// it for the signature of data under the agent flags.
type pageSigner struct {
	key  ssh.PublicKey
	sign func(data []byte, flags uint32) ([]byte, error)
}

// PublicKey returns the key the page announced.
func (s *pageSigner) PublicKey() ssh.PublicKey { return s.key }

// Algorithms returns the signature algorithms of the key in OpenSSH's preference.
func (s *pageSigner) Algorithms() []string {
	if s.key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{s.key.Type()}
}

// Sign signs data with the algorithm of the key's type.
func (s *pageSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, s.key.Type())
}

// SignWithAlgorithm asks the page to sign data with algorithm and returns the
// signature once the key verifies it, or errBadSignature.
func (s *pageSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	switch algorithm {
	case ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	case ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	}
	blob, err := s.sign(data, uint32(flags))
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if ssh.Unmarshal(blob, &sig) != nil || len(sig.Rest) != 0 || sig.Format != algorithm ||
		s.key.Verify(data, &sig) != nil {
		return nil, errBadSignature
	}
	return &sig, nil
}
