package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// moduleRoot is the root of the module from the package directory, where the tests run.
const moduleRoot = "../.."

// The variables every test environment sets: a loopback listener and the TLS pair.
const (
	envAddress = "UWSB_SERVER_ADDRESS"
	envCert    = "UWSB_SERVER_CERT"
	envKey     = "UWSB_SERVER_KEY"
	envTarget  = "UWSB_SSH_TARGET"
)

// testAddress is the loopback listen address of baseEnvironment.
const testAddress = "127.0.0.1:8443"

// pairFiles writes to a directory of t a self-signed certificate and its key as PEM
// files and returns their paths.
func pairFiles(t *testing.T) (cert, key string) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey error = %v, want nil", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bridge.example.test"},
		DNSNames: []string{"bridge.example.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatalf("x509.CreateCertificate error = %v, want nil", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey error = %v, want nil", err)
	}
	dir := t.TempDir()
	cert = writeFile(t, dir, "certificate.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	key = writeFile(t, dir, "certificate.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return cert, key
}

// writeFile writes data to the file name of dir and returns its path.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot(%s) error = %v, want nil", dir, err)
	}
	defer closeRoot(t, root)
	if err := root.WriteFile(name, data, 0o600); err != nil {
		t.Fatalf("root.WriteFile(%s) error = %v, want nil", name, err)
	}
	return filepath.Join(dir, name)
}

func closeRoot(t *testing.T, root *os.Root) {
	t.Helper()
	if err := root.Close(); err != nil {
		t.Errorf("root.Close() of %s error = %v, want nil", root.Name(), err)
	}
}

// baseEnvironment returns the variables of a loopback listener and of a TLS pair that
// pairFiles writes: the least that loads.
func baseEnvironment(t *testing.T) map[string]string {
	t.Helper()
	cert, key := pairFiles(t)
	return map[string]string{envAddress: testAddress, envCert: cert, envKey: key}
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v, want nil", filepath.Base(path), err)
	}
	return data
}

// newTable returns the setting table of a new Config.
func newTable() []setting {
	return settings(&Config{})
}

// cleanEnvironment unsets, for the test, every UWSB_ variable, so only the variables
// the test sets count.
func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, pair := range os.Environ() {
		if name, _, _ := strings.Cut(pair, "="); strings.HasPrefix(name, envPrefix) {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatalf("os.Unsetenv(%s) error = %v, want nil", name, err)
			}
		}
	}
}

// loadWith runs Load over args in a clean environment plus env and returns the
// configuration, the usage written and the error.
func loadWith(t *testing.T, env map[string]string, args []string) (*Config, string, error) {
	t.Helper()
	cleanEnvironment(t)
	for name, v := range env {
		t.Setenv(name, v)
	}
	var usage strings.Builder
	cfg, err := Load(args, &usage)
	return cfg, usage.String(), err
}

// problemsOf returns the errors err joins: none for nil, err alone for one error.
func problemsOf(err error) []error {
	if joined, ok := errors.AsType[joinedError](err); ok {
		return joined.Unwrap()
	}
	if err == nil {
		return nil
	}
	return []error{err}
}

// hasProblem reports whether err, a joined error of Load, holds a problem whose text
// starts with names and that is both ErrInvalidConfig and rule.
func hasProblem(err error, names string, rule error) bool {
	return slices.ContainsFunc(problemsOf(err), func(p error) bool {
		return strings.HasPrefix(p.Error(), names+": ") && errors.Is(p, rule) && errors.Is(p, ErrInvalidConfig)
	})
}

// wantProblem is a problem a test requires: its rule and the names it starts with.
type wantProblem struct {
	rule  error
	names string
}

// checkProblems fails t unless err, a joined error of Load, holds the problems want
// and no other.
func checkProblems(t *testing.T, what string, err error, want ...wantProblem) {
	t.Helper()
	for _, w := range want {
		if !hasProblem(err, w.names, w.rule) {
			t.Errorf("%s: Load() error = %v, want a problem of %s wrapping %v", what, err, w.names, w.rule)
		}
	}
	if got := len(problemsOf(err)); got != len(want) {
		t.Errorf("%s: Load() returned %d problems, want %d: %v", what, got, len(want), err)
	}
}

// namesOf returns the names a problem of the setting of env starts with: its flag
// and its variable.
func namesOf(env string) string {
	return flagOf(env) + " (" + env + ")"
}

// flagOf returns the flag of the variable env after a dash: its name after UWSB_, in
// lower case, each underscore a hyphen.
func flagOf(env string) string {
	return "-" + strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(env, envPrefix)), "_", "-")
}
