package config

import (
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidatePerHostWithTarget sets -conn-max-per-host beside a target, by its flag
// and by its variable: each stops the start naming both settings; left at its default
// it loads.
func TestValidatePerHostWithTarget(t *testing.T) {
	env := baseEnvironment(t)
	env[envTarget] = "192.0.2.10:22"
	if _, _, err := loadWith(t, env, []string{}); err != nil {
		t.Errorf("a target with the default per-host cap: Load() error = %v, want nil", err)
	}
	names := namesOf("UWSB_CONN_MAX_PER_HOST")
	want := names + ": set while -ssh-target (UWSB_SSH_TARGET) pins one target, whose cap is -conn-max-total " +
		"(UWSB_CONN_MAX_TOTAL)"
	_, _, err := loadWith(t, env, []string{"-conn-max-per-host=10"})
	checkProblems(t, "the flag", err, wantProblem{errPerHostWithTarget, names})
	if err == nil || err.Error() != want {
		t.Errorf("the flag: Load() error = %v, want %q", err, want)
	}
	env["UWSB_CONN_MAX_PER_HOST"] = "3"
	_, _, err = loadWith(t, env, []string{})
	checkProblems(t, "the variable", err, wantProblem{errPerHostWithTarget, names})
}

// TestValidatePerHostOverTotal sets -conn-max-per-host above -conn-max-total on the
// path route: the problem names both and their values; equal values load.
func TestValidatePerHostOverTotal(t *testing.T) {
	env := baseEnvironment(t)
	env["UWSB_CONN_MAX_TOTAL"] = "5"
	env["UWSB_CONN_MAX_PER_HOST"] = "5"
	if _, _, err := loadWith(t, env, []string{}); err != nil {
		t.Errorf("equal caps: Load() error = %v, want nil", err)
	}
	names := namesOf("UWSB_CONN_MAX_PER_HOST")
	_, _, err := loadWith(t, env, []string{"-conn-max-per-host=6"})
	checkProblems(t, "6 over 5", err, wantProblem{errPerHostOverTotal, names})
	if want := names + ": 6 is more than -conn-max-total (UWSB_CONN_MAX_TOTAL), 5"; err == nil ||
		err.Error() != want {
		t.Errorf("6 over 5: Load() error = %v, want %q", err, want)
	}
	_, _, err = loadWith(t, env, []string{"-conn-max-total=x"})
	checkProblems(t, "a total that does not read", err, wantProblem{errNotInteger, namesOf("UWSB_CONN_MAX_TOTAL")})
}

// TestValidateOpenRelay loads the path route on listeners of each kind: a loopback IP
// loads, any other listener stops the start, and a target lets it load.
func TestValidateOpenRelay(t *testing.T) {
	base := baseEnvironment(t)
	names := namesOf(envAddress)
	for _, address := range []string{"127.0.0.1:8443", "127.1.2.3:8443", "[::1]:8443"} {
		env := maps.Clone(base)
		env[envAddress] = address
		_, _, err := loadWith(t, env, []string{})
		checkProblems(t, address, err)
	}
	for _, address := range []string{":8443", "0.0.0.0:8443", "192.0.2.10:8443", "[::]:8443"} {
		env := maps.Clone(base)
		env[envAddress] = address
		_, _, err := loadWith(t, env, []string{})
		checkProblems(t, address, err, wantProblem{errOpenRelay, names})
		env[envTarget] = "device.example.test:22"
		_, _, err = loadWith(t, env, []string{})
		checkProblems(t, address+" with a target", err)
	}
	env := maps.Clone(base)
	env[envAddress] = "localhost:8443"
	_, _, err := loadWith(t, env, []string{})
	checkProblems(t, "localhost", err, wantProblem{errListenAddress, names})
	env[envAddress] = "0.0.0.0:8443"
	_, _, err = loadWith(t, env, []string{})
	want := names + `: "0.0.0.0:8443" listens beyond loopback while -ssh-target (UWSB_SSH_TARGET) is empty, ` +
		"so any client could name any host"
	if err == nil || err.Error() != want {
		t.Errorf("0.0.0.0:8443: Load() error = %v, want %q", err, want)
	}
}

// TestValidateWaitsForTheTarget gives a target that does not read beside a listener
// beyond loopback and a per-host cap: the target's problem is the only one.
func TestValidateWaitsForTheTarget(t *testing.T) {
	env := baseEnvironment(t)
	env[envAddress] = "0.0.0.0:8443"
	env[envTarget] = "device.example.test"
	env["UWSB_CONN_MAX_PER_HOST"] = "3"
	_, _, err := loadWith(t, env, []string{})
	checkProblems(t, "a target that does not read", err, wantProblem{ErrInvalidTarget, namesOf(envTarget)})
}

// TestLoadCertificateNamesBothFiles loads a missing certificate and a key of another
// certificate: each problem names both files and wraps the TLS failure.
func TestLoadCertificateNamesBothFiles(t *testing.T) {
	base := baseEnvironment(t)
	_, otherKey := pairFiles(t)
	names := namesOf(envCert) + " and " + namesOf(envKey)
	for what, change := range map[string]map[string]string{
		"a missing certificate":        {envCert: filepath.Join(t.TempDir(), "missing.crt")},
		"a key of another certificate": {envKey: otherKey},
	} {
		env := maps.Clone(base)
		maps.Copy(env, change)
		_, _, err := loadWith(t, env, []string{})
		checkProblems(t, what, err, wantProblem{errCertificate, names})
		if what == "a missing certificate" && !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: Load() error = %v, want it to wrap fs.ErrNotExist", what, err)
		}
		if !strings.Contains(err.Error(), names+": do not load as a TLS pair: ") {
			t.Errorf("%s: Load() error = %v, want the text of errCertificate after the names", what, err)
		}
	}
}
