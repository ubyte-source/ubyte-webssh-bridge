package sshclient

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// signerOf returns the page signer of key whose page answers with answer.
func signerOf(tb testing.TB, key any, answer func(data []byte, flags uint32) ([]byte, error)) *pageSigner {
	tb.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		tb.Fatalf("signer: %v", err)
	}
	return &pageSigner{key: signer.PublicKey(), sign: answer}
}

// keyringSign returns a page answer that signs with key and records the flags.
func keyringSign(tb testing.TB, key any, flags *[]uint32) func(data []byte, f uint32) ([]byte, error) {
	tb.Helper()
	page := newTestPage(tb, key)
	return func(data []byte, f uint32) ([]byte, error) {
		*flags = append(*flags, f)
		return page.Sign(tb.Context(), data, f)
	}
}

func TestPageSignerAlgorithms(t *testing.T) {
	rsaSigner := signerOf(t, newKey(t, "rsa"), nil)
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if got := rsaSigner.Algorithms(); !slices.Equal(got, want) {
		t.Errorf("RSA Algorithms() = %q, want %q", got, want)
	}
	edSigner := signerOf(t, newKey(t, "ed25519"), nil)
	if got := edSigner.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoED25519}) {
		t.Errorf("Ed25519 Algorithms() = %q", got)
	}
	if !bytes.Equal(edSigner.PublicKey().Marshal(), edSigner.key.Marshal()) {
		t.Error("PublicKey() is not the announced key")
	}
}

func TestPageSignerSignWithAlgorithmFlags(t *testing.T) {
	key := newKey(t, "rsa")
	var flags []uint32
	s := signerOf(t, key, keyringSign(t, key, &flags))
	for _, algorithm := range []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA} {
		sig, err := s.SignWithAlgorithm(nil, []byte("data"), algorithm)
		if err != nil || sig.Format != algorithm {
			t.Fatalf("SignWithAlgorithm(%s) = %v, %v", algorithm, sig, err)
		}
	}
	if !slices.Equal(flags, []uint32{4, 2, 0}) {
		t.Errorf("flags = %v, want [4 2 0]", flags)
	}
}

func TestPageSignerSign(t *testing.T) {
	key := newKey(t, "p256")
	var flags []uint32
	s := signerOf(t, key, keyringSign(t, key, &flags))
	sig, err := s.Sign(nil, []byte("data"))
	if err != nil || sig.Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("Sign = %v, %v", sig, err)
	}
}

func TestPageSignerSignWithAlgorithmRefuses(t *testing.T) {
	key := newKey(t, "ed25519")
	var flags []uint32
	sign := keyringSign(t, key, &flags)
	cases := []struct {
		name   string
		answer func(data []byte, f uint32) ([]byte, error)
		want   error
	}{
		{"a refusal", func([]byte, uint32) ([]byte, error) { return nil, errRefusedByPage }, errRefusedByPage},
		{"garbage", func([]byte, uint32) ([]byte, error) { return []byte("user01"), nil }, errBadSignature},
		{"trailing bytes", func(data []byte, f uint32) ([]byte, error) {
			blob, err := sign(data, f)
			return append(blob, 0), err
		}, errBadSignature},
		{"other data", func(data []byte, f uint32) ([]byte, error) {
			return sign(append(data, 0), f)
		}, errBadSignature},
	}
	for _, c := range cases {
		s := signerOf(t, key, c.answer)
		if _, err := s.SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoED25519); !errors.Is(err, c.want) {
			t.Errorf("%s: SignWithAlgorithm error = %v, want %v", c.name, err, c.want)
		}
	}
	s := signerOf(t, key, sign)
	if _, err := s.SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoRSA); !errors.Is(err, errBadSignature) {
		t.Errorf("another algorithm: SignWithAlgorithm error = %v, want errBadSignature", err)
	}
}

func FuzzPageSignerSignWithAlgorithm(f *testing.F) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	keyring := newTestPage(f, key).keyring
	valid := func(tb testing.TB, data []byte) []byte {
		tb.Helper()
		keys, err := keyring.List()
		if err != nil {
			tb.Fatal(err)
		}
		sig, err := keyring.Sign(keys[0], data)
		if err != nil {
			tb.Fatal(err)
		}
		return ssh.Marshal(sig)
	}
	f.Add([]byte("data"), valid(f, []byte("data")), false)
	f.Add([]byte("data"), []byte("user01"), false)
	f.Add([]byte{}, []byte{}, true)
	f.Fuzz(func(t *testing.T, data, answer []byte, answerValid bool) {
		want := valid(t, data)
		if answerValid {
			answer = want
		}
		s := signerOf(t, key, func([]byte, uint32) ([]byte, error) { return answer, nil })
		sig, err := s.SignWithAlgorithm(nil, data, ssh.KeyAlgoED25519)
		if accepted := bytes.Equal(answer, want); accepted != (err == nil) {
			t.Fatalf("SignWithAlgorithm(%x) of answer %x error = %v, want accepted %t", data, answer, err, accepted)
		}
		if err == nil && !bytes.Equal(ssh.Marshal(sig), want) {
			t.Fatalf("SignWithAlgorithm returned %x, want %x", ssh.Marshal(sig), want)
		}
		if err != nil && !errors.Is(err, errBadSignature) {
			t.Fatalf("SignWithAlgorithm error = %v, want errBadSignature", err)
		}
	})
}
