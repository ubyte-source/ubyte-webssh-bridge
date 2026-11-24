package sshclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ubyte-source/go-authware/v2/secret"

	"github.com/ubyte-source/ubyte-webssh-bridge/internal/protocol"
)

// checkMethod logs in over an in-memory pipe to d as login says, page answering, and
// fails t unless the login succeeds by want.
func checkMethod(t *testing.T, d *device, login *protocol.Login, page Page, want string) {
	t.Helper()
	c, err := logInPipe(t, d, login, page)
	if err != nil {
		t.Fatalf("logIn: %v", err)
	}
	if got := c.Method(); got != want {
		t.Errorf("Method() = %q, want %q", got, want)
	}
}

func TestPrompterMethodsPublicKey(t *testing.T) {
	cases := []struct {
		kind       string
		algorithms []string
		flags      uint32
	}{
		{"ed25519", nil, 0},
		{"p256", nil, 0},
		{"p384", nil, 0},
		{"p521", nil, 0},
		{"rsa", nil, 4},
		{"rsa", []string{ssh.KeyAlgoRSASHA256}, 2},
		{"rsa", []string{ssh.KeyAlgoRSA}, 0},
	}
	for _, c := range cases {
		t.Run(c.kind+strings.Join(c.algorithms, ""), func(t *testing.T) {
			key := newKey(t, c.kind)
			d := newDevice(t)
			d.config.PasswordCallback = nil
			d.config.PublicKeyAuthAlgorithms = c.algorithms
			login := &protocol.Login{User: testUser, Key: publicBlob(t, key)}
			d.acceptKey(login.Key)
			page := newTestPage(t, key)
			checkMethod(t, d, login, page, methodPublicKey)
			if !slices.Equal(page.flags, []uint32{c.flags}) {
				t.Errorf("sign flags = %v, want [%d]", page.flags, c.flags)
			}
		})
	}
}

func TestPrompterMethodsPublicKeyFailsOver(t *testing.T) {
	key := newKey(t, "ed25519")
	valid := func(data []byte) []byte {
		page := newTestPage(t, key)
		blob, err := page.Sign(t.Context(), data, 0)
		if err != nil {
			t.Fatal(err)
		}
		return blob
	}
	cases := []struct {
		name string
		sign func(ctx context.Context, data []byte, flags uint32) ([]byte, error)
	}{
		{"a refusal", func(context.Context, []byte, uint32) ([]byte, error) { return nil, errRefusedByPage }},
		{"a signature of other data", func(_ context.Context, data []byte, _ uint32) ([]byte, error) {
			return valid(append(data, 0)), nil
		}},
		{"another format", func(_ context.Context, data []byte, _ uint32) ([]byte, error) {
			var sig ssh.Signature
			if err := ssh.Unmarshal(valid(data), &sig); err != nil {
				return nil, fmt.Errorf("signature: %w", err)
			}
			sig.Format = ssh.KeyAlgoRSASHA512
			return ssh.Marshal(sig), nil
		}},
		{"trailing bytes", func(_ context.Context, data []byte, _ uint32) ([]byte, error) {
			return append(valid(data), 0), nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t)
			login := passwordLogin()
			login.Key = publicBlob(t, key)
			d.acceptKey(login.Key)
			page := newTestPage(t, key)
			page.sign = c.sign
			checkMethod(t, d, login, page, methodPassword)
			if len(page.flags) != 1 {
				t.Errorf("sign requests = %d, want 1", len(page.flags))
			}
		})
	}
}

func TestPrompterChallengeOneRound(t *testing.T) {
	d := newDevice(t)
	d.interactive(prompt("Password: ", false, testPassword))
	page := newTestPage(t, nil)
	checkMethod(t, d, passwordLogin(), page, methodKeyboard)
	if len(page.challenges) != 0 {
		t.Errorf("the page saw %d challenges, want none", len(page.challenges))
	}
}

func TestPrompterChallengeThreeRounds(t *testing.T) {
	d := newDevice(t)
	d.interactive(prompt("Password: ", false, testPassword), prompt("Code: ", true, "123456"),
		prompt("Token: ", false, "654321"))
	page := newTestPage(t, nil, []string{"123456"}, []string{"654321"})
	checkMethod(t, d, passwordLogin(), page, methodKeyboard)
	want := []protocol.Challenge{
		{Prompts: []protocol.Prompt{{Text: "Code: ", Echo: true}}},
		{Prompts: []protocol.Prompt{{Text: "Token: "}}},
	}
	if len(page.challenges) != len(want) {
		t.Fatalf("challenges = %+v, want %+v", page.challenges, want)
	}
	for i, c := range page.challenges {
		if c.Name != want[i].Name || !slices.Equal(c.Prompts, want[i].Prompts) {
			t.Errorf("challenge %d = %+v, want %+v", i, c, want[i])
		}
	}
}

func TestPrompterChallengeWithoutPrompts(t *testing.T) {
	cases := []struct {
		name, instruction string
		want              []string
	}{
		{"Notice", "Read me.", []string{"Notice\nRead me."}},
		{"Notice", "", []string{"Notice"}},
		{"", "Read me.", []string{"Read me."}},
		{"", "", nil},
	}
	for _, c := range cases {
		d := newDevice(t)
		d.interactive(round{name: c.name, instruction: c.instruction}, prompt("Password: ", false, testPassword))
		page := newTestPage(t, nil)
		checkMethod(t, d, passwordLogin(), page, methodKeyboard)
		if !slices.Equal(page.banners, c.want) {
			t.Errorf("banners = %q, want %q", page.banners, c.want)
		}
	}
}

func TestPrompterChallengeBounds(t *testing.T) {
	many := func(n int) round {
		r := round{questions: make([]string, n), echos: make([]bool, n), want: make([]string, n)}
		for i := range n {
			r.questions[i], r.echos[i], r.want[i] = "Q: ", true, "a"
		}
		return r
	}
	for _, c := range []struct {
		name  string
		round round
		valid bool
	}{
		{"16 prompts", many(16), true},
		{"17 prompts", many(17), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t)
			d.interactive(c.round)
			page := newTestPage(t, nil, c.round.want, c.round.want, c.round.want)
			login := &protocol.Login{User: testUser}
			if c.valid {
				checkMethod(t, d, login, page, methodKeyboard)
				return
			}
			_, err := logInPipe(t, d, login, page)
			if !errors.Is(err, ErrAuthFailed) || len(page.challenges) != 0 {
				t.Errorf("logIn error = %v after %d challenges, want ErrAuthFailed after none", err,
					len(page.challenges))
			}
		})
	}
}

// TestPrompterChallengeLongTexts gives a round a name, an instruction and a prompt past
// what the page shows: they reach the page whole, and the message to the page cuts
// them.
func TestPrompterChallengeLongTexts(t *testing.T) {
	r := prompt(strings.Repeat("q", 1025), true, "a")
	r.name, r.instruction = strings.Repeat("n", 4097), strings.Repeat("i", 4097)
	d := newDevice(t)
	d.interactive(r)
	page := newTestPage(t, nil, r.want)
	checkMethod(t, d, &protocol.Login{User: testUser}, page, methodKeyboard)
	want := protocol.Challenge{Name: r.name, Instruction: r.instruction,
		Prompts: []protocol.Prompt{{Text: r.questions[0], Echo: true}}}
	if len(page.challenges) != 1 || page.challenges[0].Name != want.Name ||
		page.challenges[0].Instruction != want.Instruction || !slices.Equal(page.challenges[0].Prompts, want.Prompts) {
		t.Errorf("challenges = %d, want the round whole", len(page.challenges))
	}
}

func TestPrompterChallengeRounds(t *testing.T) {
	for _, n := range []int{32, 33} {
		rounds := make([]round, n)
		answers := make([][]string, n)
		for i := range rounds {
			rounds[i], answers[i] = prompt("Code: ", true, "123456"), []string{"123456"}
		}
		d := newDevice(t)
		d.interactive(rounds...)
		login, page := &protocol.Login{User: testUser}, newTestPage(t, nil, answers...)
		if n == 32 {
			checkMethod(t, d, login, page, methodKeyboard)
			continue
		}
		if _, err := logInPipe(t, d, login, page); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("logIn with %d rounds error = %v, want ErrAuthFailed", n, err)
		}
	}
}

func TestPrompterPasswordAsked(t *testing.T) {
	d := newDevice(t)
	page := newTestPage(t, nil, []string{testPassword})
	checkMethod(t, d, &protocol.Login{User: testUser}, page, methodPassword)
	want := protocol.Challenge{Prompts: []protocol.Prompt{{Text: "user01@192.0.2.10's password: "}}}
	if len(page.challenges) != 1 || !slices.Equal(page.challenges[0].Prompts, want.Prompts) {
		t.Errorf("challenges = %+v, want %+v", page.challenges, want)
	}
}

func TestPrompterPasswordTypedThenAsked(t *testing.T) {
	d := newDevice(t)
	page := newTestPage(t, nil, []string{testPassword})
	login := &protocol.Login{User: testUser, Password: secret.New("wrong")}
	checkMethod(t, d, login, page, methodPassword)
	if len(page.challenges) != 1 {
		t.Errorf("challenges = %d, want 1", len(page.challenges))
	}
}

func TestPrompterPasswordThreeTries(t *testing.T) {
	d := newDevice(t)
	page := newTestPage(t, nil, []string{"wrong"}, []string{"wrong"}, []string{"wrong"}, []string{testPassword})
	_, err := logInPipe(t, d, &protocol.Login{User: testUser}, page)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("logIn error = %v, want ErrAuthFailed", err)
	}
	if len(page.challenges) != 3 {
		t.Errorf("challenges = %d, want 3", len(page.challenges))
	}
}

func TestPrompterAskAnswerCount(t *testing.T) {
	d := newDevice(t)
	page := newTestPage(t, nil, []string{testPassword, testPassword})
	_, err := logInPipe(t, d, &protocol.Login{User: testUser}, page)
	if !errors.Is(err, ErrAuthFailed) || len(page.challenges) != 1 {
		t.Fatalf("logIn error = %v after %d challenges, want ErrAuthFailed after 1", err, len(page.challenges))
	}
}

// TestPrompterAskPageFails asks a page that fails: ask returns the page's error.
func TestPrompterAskPageFails(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errRefusedByPage)
	p := &prompter{page: newTestPage(t, nil)}
	answers, err := p.ask(ctx, protocol.Challenge{Prompts: []protocol.Prompt{{Text: "Code: "}}})
	if !errors.Is(err, errRefusedByPage) || answers != nil {
		t.Errorf("ask = %q, %v, want the page's error", answers, err)
	}
}

func TestPrompterBanner(t *testing.T) {
	d := newDevice(t)
	d.config.BannerCallback = func(ssh.ConnMetadata) string { return "Authorized use only.\r\n" }
	page := newTestPage(t, nil)
	checkMethod(t, d, passwordLogin(), page, methodPassword)
	if want := []string{"Authorized use only.\r\n"}; !slices.Equal(page.banners, want) {
		t.Errorf("banners = %q, want %q", page.banners, want)
	}
}

func TestPrompterZero(t *testing.T) {
	login := passwordLogin()
	p := &prompter{login: login}
	p.zero()
	if !login.Password.IsZero() {
		t.Error("zero kept the password")
	}
}

func TestPrompterMethodsNone(t *testing.T) {
	d := newDevice(t)
	d.config.NoClientAuth = true
	checkMethod(t, d, passwordLogin(), newTestPage(t, nil), methodNone)
}

func TestPrompterShowFails(t *testing.T) {
	d := newDevice(t)
	d.config.BannerCallback = func(ssh.ConnMetadata) string { return "Authorized use only.\r\n" }
	page := newTestPage(t, nil)
	page.bannerErr = errPageGone
	if _, err := logInPipe(t, d, passwordLogin(), page); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("logIn error = %v, want ErrAuthFailed", err)
	}
	if err := (&prompter{page: page}).show(t.Context(), "Notice"); !errors.Is(err, errPageGone) {
		t.Errorf("show error = %v, want the page's error", err)
	}
}
