package sshclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// The bounds of a login: the tries of keyboard-interactive and of the password, and the
// rounds and prompts of keyboard-interactive.
const (
	loginTries = 3
	maxRounds  = 32
	maxPrompts = 16
)

// The login methods as Method names them; none is a device that asks for no
// credential.
const (
	methodNone      = "none"
	methodPublicKey = "publickey"
	methodKeyboard  = "keyboard-interactive"
	methodPassword  = "password"
)

var (
	// errTooManyRounds reports a keyboard-interactive login past maxRounds rounds.
	errTooManyRounds = errors.New(errPrefix + "too many keyboard-interactive rounds")
	// errTooManyPrompts reports a keyboard-interactive round past maxPrompts prompts.
	errTooManyPrompts = errors.New(errPrefix + "too many keyboard-interactive prompts")
	// errAnswerCount reports answers of the page that are not one per prompt.
	errAnswerCount = errors.New(errPrefix + "answers are not one per prompt")
)

// prompter runs the login methods of one connection for the user behind page, who
// typed login; x/crypto calls them on the one goroutine of the handshake.
type prompter struct {
	page   Page
	login  *protocol.Login
	host   string
	method string
	rounds int
	// typedAnswered and typedSent record the one use each of the typed password, by
	// keyboard-interactive and by the password method.
	typedAnswered bool
	typedSent     bool
}

// methods returns the login methods in OpenSSH's order: the page's key when it holds
// one, keyboard-interactive, then the password.
func (p *prompter) methods(ctx context.Context, key ssh.PublicKey) []ssh.AuthMethod {
	var out []ssh.AuthMethod
	if key != nil {
		signer := &pageSigner{key: key, sign: func(data []byte, flags uint32) ([]byte, error) {
			p.method = methodPublicKey
			return p.page.Sign(ctx, data, flags)
		}}
		out = append(out, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return []ssh.Signer{signer}, nil }))
	}
	return append(out,
		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(p.challenge(ctx)), loginTries),
		ssh.RetryableAuthMethod(ssh.PasswordCallback(p.password(ctx)), loginTries))
}

// challenge returns the keyboard-interactive callback: a round without prompts
// reaches the page as a banner, the first lone prompt without echo takes the typed
// password, and every other round goes to the page.
func (p *prompter) challenge(ctx context.Context) ssh.KeyboardInteractiveChallenge {
	return func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		p.method = methodKeyboard
		p.rounds++
		switch {
		case p.rounds > maxRounds:
			return nil, errTooManyRounds
		case len(questions) > maxPrompts:
			return nil, errTooManyPrompts
		case len(questions) == 0:
			return nil, p.notice(ctx, name, instruction)
		case len(questions) == 1 && !echos[0] && !p.typedAnswered && !p.login.Password.IsZero():
			p.typedAnswered = true
			return []string{p.login.Password.Reveal()}, nil
		}
		c := protocol.Challenge{Name: name, Instruction: instruction, Prompts: make([]protocol.Prompt, len(questions))}
		for i, q := range questions {
			c.Prompts[i] = protocol.Prompt{Text: q, Echo: echos[i]}
		}
		return p.ask(ctx, c)
	}
}

// notice shows the page the name and the instruction of a round without prompts, the
// ones that are not empty, joined by a newline.
func (p *prompter) notice(ctx context.Context, name, instruction string) error {
	text := strings.Join(slices.DeleteFunc([]string{name, instruction}, func(s string) bool { return s == "" }), "\n")
	if text == "" {
		return nil
	}
	return p.show(ctx, text)
}

// password returns the password callback: the typed password on the first call, then
// the page's answer to a password prompt.
func (p *prompter) password(ctx context.Context) func() (string, error) {
	return func() (string, error) {
		p.method = methodPassword
		if !p.typedSent && !p.login.Password.IsZero() {
			p.typedSent = true
			return p.login.Password.Reveal(), nil
		}
		prompt := protocol.Prompt{Text: p.login.User + "@" + p.host + "'s password: "}
		answers, err := p.ask(ctx, protocol.Challenge{Prompts: []protocol.Prompt{prompt}})
		if err != nil {
			return "", err
		}
		return answers[0], nil
	}
}

// ask returns the page's answers to c, one per prompt.
func (p *prompter) ask(ctx context.Context, c protocol.Challenge) ([]string, error) {
	values, err := p.page.Answer(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("answer: %w", err)
	}
	if len(values) != len(c.Prompts) {
		return nil, errAnswerCount
	}
	answers := make([]string, len(values))
	for i, v := range values {
		answers[i] = v.Reveal()
	}
	return answers, nil
}

// banner returns the banner callback, which shows the page each banner of the device.
func (p *prompter) banner(ctx context.Context) ssh.BannerCallback {
	return func(message string) error { return p.show(ctx, message) }
}

// show shows the page text, a banner.
func (p *prompter) show(ctx context.Context, text string) error {
	if err := p.page.Banner(ctx, text); err != nil {
		return fmt.Errorf("banner: %w", err)
	}
	return nil
}

// zero drops the typed password the methods read.
func (p *prompter) zero() {
	p.login.Password = secret.Value{}
}
