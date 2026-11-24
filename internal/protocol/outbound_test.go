package protocol

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
)

// encodeFields returns the frame the Encode function of the type of f writes for it.
func encodeFields(t *testing.T, f *bridgeFields) []byte {
	t.Helper()
	switch f.Type {
	case "banner":
		return EncodeBanner(f.Text)
	case "challenge":
		c := Challenge{Name: f.Name, Instruction: f.Instruction}
		for _, p := range f.Prompts {
			c.Prompts = append(c.Prompts, Prompt(p))
		}
		return EncodeChallenge(c)
	case "sign":
		data, err := base64.StdEncoding.DecodeString(f.Data)
		if err != nil {
			t.Fatalf("data: %v", err)
		}
		return EncodeSign(f.ID, data, f.Flags)
	case "ready":
		return EncodeReady()
	}
	e := Exit{Signal: f.Signal}
	if f.Status != nil {
		e.Status, e.HasStatus = *f.Status, true
	}
	return EncodeExit(e)
}

// checkCorpus checks that the encoder of each corpus frame of type typ writes it.
func checkCorpus(t *testing.T, typ string) {
	t.Helper()
	c := loadCorpus(t)
	seen := 0
	for i := range c.Bridge {
		b := &c.Bridge[i]
		if b.Fields.Type != typ {
			continue
		}
		seen++
		if got := string(encodeFields(t, &b.Fields)); got != b.Frame {
			t.Errorf("%s: encoded %s, want %s", b.Name, got, b.Frame)
		}
	}
	if seen == 0 {
		t.Errorf("the corpus holds no %s frame", typ)
	}
}

func TestEncodeBannerCorpus(t *testing.T) { checkCorpus(t, "banner") }

func TestEncodeChallengeCorpus(t *testing.T) { checkCorpus(t, "challenge") }

func TestEncodeSignCorpus(t *testing.T) { checkCorpus(t, "sign") }

func TestEncodeReadyCorpus(t *testing.T) { checkCorpus(t, "ready") }

func TestEncodeExitCorpus(t *testing.T) { checkCorpus(t, "exit") }

func TestEncodeBannerWritesInvalidUTF8AsReplacement(t *testing.T) {
	got := string(EncodeBanner("a\xffb\xe2\x82c"))
	if want := `{"type":"banner","text":"a` + "�" + `b` + "��" + `c"}`; got != want {
		t.Errorf("EncodeBanner = %s, want %s", got, want)
	}
}

func TestEncodeChallengeWritesInvalidUTF8AsReplacement(t *testing.T) {
	got := string(EncodeChallenge(Challenge{Name: "n\xff", Instruction: "\xc3", Prompts: []Prompt{{Text: "\x80: "}}}))
	want := `{"type":"challenge","name":"n` + "�" + `","instruction":"` + "�" +
		`","prompts":[{"text":"` + "�" + `: ","echo":false}]}`
	if got != want {
		t.Errorf("EncodeChallenge = %s, want %s", got, want)
	}
}

func TestEncodeExitWritesInvalidUTF8AsReplacement(t *testing.T) {
	got := string(EncodeExit(Exit{Signal: "\xfeINT", Status: 130, HasStatus: true}))
	if want := `{"type":"exit","status":130,"signal":"` + "�" + `INT"}`; got != want {
		t.Errorf("EncodeExit = %s, want %s", got, want)
	}
}

// replacement is U+FFFD, which the encoders write for each invalid byte: 3 bytes of
// UTF-8 for the 1 byte it stands for.
const replacement = "\uFFFD"

// cutCase is a text and what an encoder sends of it under a bound.
type cutCase struct{ name, text, want string }

// cutCases returns the cases of a bound of n bytes: valid text and invalid bytes at
// the bound and past it, and a rune across it.
func cutCases(n int) []cutCase {
	a := func(k int) string { return strings.Repeat("a", k) }
	bad := strings.Repeat("\xff", n/3+1)
	return []cutCase{
		{"text at the bound", a(n), a(n)},
		{"text past the bound", a(n + 1), a(n)},
		{"a rune across the bound", a(n-1) + "€", a(n - 1)},
		{"a rune ending at the bound", a(n-3) + "€b", a(n-3) + "€"},
		{"an invalid byte ending at the bound", a(n-3) + "\xff", a(n-3) + replacement},
		{"an invalid byte across the bound", a(n-2) + "\xff", a(n - 2)},
		{"an invalid byte past the bound", a(n) + "\xff", a(n)},
		{"invalid bytes past the bound", bad, strings.Repeat(replacement, n/3)},
	}
}

func TestEncodeBannerCutsText(t *testing.T) {
	for _, c := range cutCases(16384) {
		got := string(EncodeBanner(c.text))
		if want := `{"type":"banner","text":"` + c.want + `"}`; got != want {
			t.Errorf("%s: EncodeBanner wrote %d bytes, want %d", c.name, len(got), len(want))
		}
	}
}

func TestEncodeChallengeCutsTexts(t *testing.T) {
	texts, prompts := cutCases(4096), cutCases(1024)
	for i := range texts {
		got := string(EncodeChallenge(Challenge{Name: texts[i].text, Instruction: texts[i].text,
			Prompts: []Prompt{{Text: prompts[i].text}}}))
		want := `{"type":"challenge","name":"` + texts[i].want + `","instruction":"` + texts[i].want +
			`","prompts":[{"text":"` + prompts[i].want + `","echo":false}]}`
		if got != want {
			t.Errorf("%s: EncodeChallenge wrote %d bytes, want %d", texts[i].name, len(got), len(want))
		}
	}
}

func TestEncodeExitCutsSignal(t *testing.T) {
	for _, c := range cutCases(32) {
		got := string(EncodeExit(Exit{Signal: c.text}))
		if want := `{"type":"exit","signal":"` + c.want + `"}`; got != want {
			t.Errorf("%s: EncodeExit = %s, want %s", c.name, got, want)
		}
	}
}

// shown returns s as the page reads it under a bound of n bytes: each invalid byte as
// U+FFFD, then the runes that fit.
func shown(s string, n int) string {
	runes := []rune(s)
	for len(string(runes)) > n {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}

// decodedAs reports whether got holds the challenge c as the page reads it: each
// invalid byte of its texts as U+FFFD, each text within its bound.
func decodedAs(got *bridgeFields, c *Challenge) bool {
	same := got.Type == "challenge" && got.Name == shown(c.Name, 4096) &&
		got.Instruction == shown(c.Instruction, 4096) && len(got.Prompts) == len(c.Prompts) && got.Text == "" &&
		got.Status == nil
	for i := range got.Prompts {
		same = same && got.Prompts[i].Text == shown(c.Prompts[i].Text, 1024) &&
			got.Prompts[i].Echo == c.Prompts[i].Echo
	}
	return same
}

func FuzzEncodeChallenge(f *testing.F) {
	f.Add("", "", "Password: ", "", false, false)
	f.Add("Two-factor", "Enter the code.", "Password: ", "Code: ", false, true)
	f.Add("\"n\\\x02", "line\n\t�", "\xff\xe2\x82: ", "\x00\x7f", true, false)
	f.Add(strings.Repeat("n", 4095)+"\xff", strings.Repeat("\xfe", 1366), strings.Repeat("é", 513), "\xff", false, true)
	f.Fuzz(func(t *testing.T, name, instruction, first, second string, firstEcho, secondEcho bool) {
		in := Challenge{Name: name, Instruction: instruction,
			Prompts: []Prompt{{Text: first, Echo: firstEcho}, {Text: second, Echo: secondEcho}}}
		frame := EncodeChallenge(in)
		var got bridgeFields
		err := json.Unmarshal(frame, &got, jsontext.AllowDuplicateNames(false), json.RejectUnknownMembers(true))
		if err != nil {
			t.Fatalf("EncodeChallenge wrote %q: %v", frame, err)
		}
		if !decodedAs(&got, &in) {
			t.Fatalf("EncodeChallenge(%+v) wrote %q", in, frame)
		}
	})
}
