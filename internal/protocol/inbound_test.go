package protocol

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// describe renders m with its secrets revealed, so that two messages compare as text.
func describe(m Message) string {
	switch m := m.(type) {
	case Connect:
		return fmt.Sprintf("connect user=%q password=%q key=%x size=%v", m.Login.User, m.Login.Password.Reveal(),
			m.Login.Key, m.Size)
	case Answers:
		values := make([]string, 0, len(m.Values))
		for _, v := range m.Values {
			values = append(values, v.Reveal())
		}
		return fmt.Sprintf("answers %q", values)
	case Signature:
		return fmt.Sprintf("signature id=%d blob=%x", m.ID, m.Blob)
	case Refusal:
		return fmt.Sprintf("refusal id=%d", m.ID)
	case Resize:
		return fmt.Sprintf("resize size=%v", m.Size)
	}
	return fmt.Sprintf("no message %T", m)
}

// fromFields returns the message the fields of a valid page frame name.
func fromFields(t *testing.T, f *pageFields) Message {
	t.Helper()
	bytesOf := func(text string) []byte {
		b, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			t.Fatalf("base64 field: %v", err)
		}
		return b
	}
	size := Size{Cols: f.Cols, Rows: f.Rows}
	switch f.Type {
	case "connect":
		login := Login{User: f.User, Key: bytesOf(f.Key)}
		if f.Password != nil {
			login.Password = secret.New(*f.Password)
		}
		return Connect{Size: size, Login: login}
	case "answers":
		values := make([]secret.Value, 0, len(f.Answers))
		for _, a := range f.Answers {
			values = append(values, secret.New(a))
		}
		return Answers{Values: values}
	case "signature":
		return Signature{ID: f.ID, Blob: bytesOf(f.Signature)}
	case "refusal":
		return Refusal{ID: f.ID}
	}
	return Resize{Size: size}
}

func TestDecodeCorpus(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Page) == 0 {
		t.Fatal("the corpus holds no page frame")
	}
	for i := range c.Page {
		p := &c.Page[i]
		t.Run(p.Name, func(t *testing.T) {
			got, err := Decode(p.data())
			if !p.Valid {
				if !errors.Is(err, ErrInvalidMessage) || got != nil {
					t.Fatalf("Decode = %v, %v, want nil, ErrInvalidMessage", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if g, w := describe(got), describe(fromFields(t, &p.Fields)); g != w {
				t.Errorf("Decode = %s, want %s", g, w)
			}
		})
	}
}

// decodeCase is a frame with its verdict.
type decodeCase struct {
	name  string
	frame string
	valid bool
}

// runDecodeCases checks the verdict of Decode on each case.
func runDecodeCases(t *testing.T, cases []decodeCase) {
	t.Helper()
	for _, c := range cases {
		_, err := Decode([]byte(c.frame))
		switch {
		case c.valid && err != nil:
			t.Errorf("%s: Decode: %v", c.name, err)
		case !c.valid && !errors.Is(err, ErrInvalidMessage):
			t.Errorf("%s: Decode error = %v, want ErrInvalidMessage", c.name, err)
		}
	}
}

// connectFrame returns a connect frame of user with the members between it and the
// size, and the size cols by rows.
func connectFrame(user, rest string, cols, rows int) string {
	return fmt.Sprintf(`{"type":"connect","user":%q%s,"cols":%d,"rows":%d}`, user, rest, cols, rows)
}

// answersFrame returns an answers frame of n answers of size bytes each.
func answersFrame(n, size int) string {
	answers := make([]string, n)
	for i := range answers {
		answers[i] = strconv.Quote(strings.Repeat("a", size))
	}
	return `{"type":"answers","answers":[` + strings.Join(answers, ",") + `]}`
}

func TestDecodeBoundsUserPasswordAnswer(t *testing.T) {
	password := func(n int) string { return fmt.Sprintf(`,"password":%q`, strings.Repeat("p", n)) }
	runDecodeCases(t, []decodeCase{
		{"user of 1 byte", connectFrame("u", "", 1, 1), true},
		{"user of 256 bytes", connectFrame(strings.Repeat("u", 256), "", 1, 1), true},
		{"user of 0 bytes", connectFrame("", "", 1, 1), false},
		{"user of 257 bytes", connectFrame(strings.Repeat("u", 257), "", 1, 1), false},
		{"password of 1 byte", connectFrame("user01", password(1), 1, 1), true},
		{"password of 1024 bytes", connectFrame("user01", password(1024), 1, 1), true},
		{"password of 0 bytes", connectFrame("user01", password(0), 1, 1), false},
		{"password of 1025 bytes", connectFrame("user01", password(1025), 1, 1), false},
		{"answer of 0 bytes", answersFrame(1, 0), true},
		{"answer of 1024 bytes", answersFrame(1, 1024), true},
		{"answer of 1025 bytes", answersFrame(1, 1025), false},
	})
}

// TestDecodeBoundsUserControlBytes decodes users whose JSON escapes a byte: a control
// byte or DEL breaks the rule, the other bytes do not.
func TestDecodeBoundsUserControlBytes(t *testing.T) {
	frame := func(c int) string { return fmt.Sprintf(`{"type":"connect","user":"user\u%04x","cols":1,"rows":1}`, c) }
	for c := range 0x80 {
		_, err := Decode([]byte(frame(c)))
		var broken invalid
		control := c < 0x20 || c == 0x7f
		if control != (errors.As(err, &broken) && broken == invalid{member: nameUser, rule: ruleControl}) ||
			!control && err != nil {
			t.Errorf("Decode(%s) error = %v, want a control byte %t", frame(c), err, control)
		}
	}
}

func TestDecodeBoundsBase64(t *testing.T) {
	text := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	key := func(s string) string { return connectFrame("user01", `,"key":"`+s+`"`, 1, 1) }
	signature := func(s string) string { return `{"type":"signature","id":1,"signature":"` + s + `"}` }
	runDecodeCases(t, []decodeCase{
		{"key of 4 characters", key(text(1)), true},
		{"key of 4096 characters", key(text(3072)), true},
		{"key of 4097 characters", key(text(3072) + "A"), false},
		{"key of 4100 characters", key(text(3075)), false},
		{"key of 0 characters", key(""), false},
		{"signature of 4096 characters", signature(text(3072)), true},
		{"signature of 4100 characters", signature(text(3075)), false},
		{"signature of 0 characters", signature(""), false},
		{"key without padding", key("AAA"), false},
		{"key with a line feed", key(`AAAA\nAAAA`), false},
		{"key with padding bits", key("AB=="), false},
		{"key in base64url", key("-_-_"), false},
	})
}

func TestDecodeBoundsAnswerCount(t *testing.T) {
	runDecodeCases(t, []decodeCase{
		{"no answer", answersFrame(0, 1), true},
		{"16 answers", answersFrame(16, 1), true},
		{"17 answers", answersFrame(17, 1), false},
	})
}

func TestDecodeBoundsSize(t *testing.T) {
	resize := func(cols, rows int) string { return fmt.Sprintf(`{"type":"resize","cols":%d,"rows":%d}`, cols, rows) }
	runDecodeCases(t, []decodeCase{
		{"resize 1 by 1", resize(1, 1), true},
		{"resize 999 by 999", resize(999, 999), true},
		{"resize cols 0", resize(0, 1), false},
		{"resize rows 0", resize(1, 0), false},
		{"resize cols 1000", resize(1000, 1), false},
		{"resize rows 1000", resize(1, 1000), false},
		{"connect 1 by 1", connectFrame("user01", "", 1, 1), true},
		{"connect 999 by 999", connectFrame("user01", "", 999, 999), true},
		{"connect cols 0", connectFrame("user01", "", 0, 1), false},
		{"connect rows 1000", connectFrame("user01", "", 1, 1000), false},
	})
}

func TestDecodeBoundsID(t *testing.T) {
	refusal := func(id string) string { return `{"type":"refusal","id":` + id + `}` }
	runDecodeCases(t, []decodeCase{
		{"id 1", refusal("1"), true},
		{"id 4294967295", refusal("4294967295"), true},
		{"id 0", refusal("0"), false},
		{"id 4294967296", refusal("4294967296"), false},
		{"id past uint64", refusal("18446744073709551616"), false},
		{"id with a fraction", refusal("1.0"), false},
		{"id with an exponent", refusal("1e0"), false},
		{"id with a sign", refusal("-1"), false},
		{"id with a leading zero", refusal("01"), false},
	})
}

func TestDecodeRefusesNestingPastTwo(t *testing.T) {
	runDecodeCases(t, []decodeCase{
		{"answers nested 2", `{"type":"answers","answers":["a"]}`, true},
		{"answers nested 3", `{"type":"answers","answers":[["a"]]}`, false},
		{"an object nested 3", `{"type":"answers","answers":[{"a":["b"]}]}`, false},
	})
}

func TestDecodeAcceptsAnyMemberOrder(t *testing.T) {
	frame := `{"rows":2,"key":"AAAA","cols":3,"password":"secret01","user":"user01","type":"connect"}`
	got, err := Decode([]byte(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := Connect{Login: Login{User: "user01", Password: secret.New("secret01"), Key: []byte{0, 0, 0}},
		Size: Size{Cols: 3, Rows: 2}}
	if g, w := describe(got), describe(want); g != w {
		t.Errorf("Decode = %s, want %s", g, w)
	}
}

// TestDecodeConnectWithoutKey decodes a connect that holds no key: its login has none.
func TestDecodeConnectWithoutKey(t *testing.T) {
	got, err := Decode([]byte(connectFrame("user01", "", 80, 24)))
	connect, ok := got.(Connect)
	if err != nil || !ok || connect.Login.Key != nil {
		t.Errorf("Decode = %s, %v, want a connect without a key", describe(got), err)
	}
}

func TestDecodeKeepsNoReference(t *testing.T) {
	frames := []string{
		`{"type":"connect","user":"user01","password":"secret01","key":"AAECAw==","cols":80,"rows":24}`,
		`{"type":"connect","user":"user01","password":"secret01","cols":80,"rows":24}`,
		`{"type":"answers","answers":["answer01","answer02"]}`,
		`{"type":"signature","id":7,"signature":"AAECAw=="}`,
	}
	for _, frame := range frames {
		data := []byte(frame)
		got, err := Decode(data)
		if err != nil {
			t.Fatalf("Decode(%s): %v", frame, err)
		}
		before := describe(got)
		clear(data)
		if after := describe(got); after != before {
			t.Errorf("Decode(%s) after the frame was overwritten = %s, want %s", frame, after, before)
		}
	}
}

func TestMessageKind(t *testing.T) {
	cases := []struct {
		message Message
		want    Kind
	}{
		{Connect{}, KindConnect}, {Answers{}, KindAnswers}, {Signature{}, KindSignature},
		{Refusal{}, KindRefusal}, {Resize{}, KindResize},
	}
	for i, c := range cases {
		if got := c.message.Kind(); got != c.want || int(got) != i+1 {
			t.Errorf("%T.Kind() = %d, want %d", c.message, got, c.want)
		}
	}
}

func TestDecodeMasksSecrets(t *testing.T) {
	const password, answer = "secret01", "answer01"
	frames := []string{
		connectFrame("user01", `,"password":"`+password+`"`, 1, 1),
		`{"type":"answers","answers":["` + answer + `"]}`,
	}
	for _, frame := range frames {
		m, err := Decode([]byte(frame))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		var logged strings.Builder
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("message", slog.Any("message", m))
		marshaled, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		text := fmt.Sprintf("%v %+v %#v %s", m, m, m, m) + logged.String() + string(marshaled)
		if strings.Contains(text, password) || strings.Contains(text, answer) || !strings.Contains(text, "***") {
			t.Errorf("printed message %s, want every secret as ***", text)
		}
	}
}

func TestDecodeErrorHoldsNoValue(t *testing.T) {
	const value = "secret01"
	frames := []string{
		connectFrame("user01", `,"password":"`+strings.Repeat(value, 200)+`"`, 1, 1),
		`{"type":"answers","answers":["` + value + `",1]}`,
		`{"type":"answers","answers":["` + strings.Repeat(value, 200) + `"]}`,
		`{"type":"connect","user":"user01","` + value + `":"` + value + `","cols":1,"rows":1}`,
		`{"type":"` + value + `"}`,
		`{"type":"connect","user":"` + value + `\u0001","cols":1,"rows":1}`,
		`{"type":"connect","user":"user01","key":"` + value + `!","cols":1,"rows":1}`,
		`{"type":"resize","cols":` + strconv.Itoa(len(value)*1000) + `,"rows":1}`,
	}
	for _, frame := range frames {
		_, err := Decode([]byte(frame))
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("Decode(%s) error = %v, want ErrInvalidMessage", frame, err)
		}
		if text := err.Error(); strings.Contains(text, value) || strings.Contains(text, "8000") {
			t.Errorf("Decode(%s) error = %q, want no value of the frame", frame, text)
		}
	}
}

func TestDecodeErrorNamesMemberAndRule(t *testing.T) {
	cases := []struct{ frame, want string }{
		{`[]`, "protocol: invalid message: message " + ruleJSON},
		{`{"type":"resize","cols":1,"rows":1,"x":1}`, "protocol: invalid message: message " + ruleUnknown},
		{`{"cols":1,"rows":1}`, "protocol: invalid message: type " + ruleType},
		{`{"type":"refusal","id":1,"cols":1}`, "protocol: invalid message: cols " + ruleTaken},
		{`{"type":"answers","answers":["a"],"cols":1}`, "protocol: invalid message: cols " + ruleTaken},
		{`{"type":"resize","cols":1}`, "protocol: invalid message: rows " + ruleMissing},
		{`{"type":"connect","user":1,"cols":1,"rows":1}`, "protocol: invalid message: user " + ruleString},
		{connectFrame("", "", 1, 1), "protocol: invalid message: user is not 1 to 256 bytes long"},
		{connectFrame("a\tb", "", 1, 1), "protocol: invalid message: user " + ruleControl},
		{connectFrame("user01", `,"key":"AAA"`, 1, 1), "protocol: invalid message: key " + ruleBase64},
		{connectFrame("user01", `,"key":"`+strings.Repeat("A", 4097)+`"`, 1, 1),
			"protocol: invalid message: key is not 1 to 4096 bytes long"},
		{`{"type":"resize","cols":0,"rows":1}`, "protocol: invalid message: cols is not an integer from 1 to 999"},
		{`{"type":"refusal","id":0}`, "protocol: invalid message: id is not an integer from 1 to 4294967295"},
		{`{"type":"answers","answers":[1]}`, "protocol: invalid message: answers " + ruleStrings},
		{answersFrame(17, 1), "protocol: invalid message: answers " + ruleAnswers},
		{answersFrame(1, 1025), "protocol: invalid message: answers " + ruleAnswer},
	}
	for _, c := range cases {
		_, err := Decode([]byte(c.frame))
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("Decode(%s) error = %v, want ErrInvalidMessage", c.frame, err)
		}
		if got := err.Error(); got != c.want {
			t.Errorf("Decode(%s) error = %q, want %q", c.frame, got, c.want)
		}
	}
}

// oracleMembers returns the members of each type of the page's messages.
func oracleMembers() map[string][]string {
	return map[string][]string{
		"connect":   {"type", "user", "password", "key", "cols", "rows"},
		"answers":   {"type", "answers"},
		"signature": {"type", "id", "signature"},
		"refusal":   {"type", "id"},
		"resize":    {"type", "cols", "rows"},
	}
}

// oracleReader reads the members of one frame for the oracle; ok turns false at the
// first broken rule.
type oracleReader struct {
	members map[string]jsontext.Value
	ok      bool
}

// oracle decodes data by encoding/json/v2 and applies the bounds of the page's
// messages by its own code.
func oracle(data []byte) (Message, bool) {
	var members map[string]jsontext.Value
	if json.Unmarshal(data, &members, jsontext.AllowDuplicateNames(false)) != nil || members == nil {
		return nil, false
	}
	var typ string
	if json.Unmarshal(members["type"], &typ) != nil {
		return nil, false
	}
	names, ok := oracleMembers()[typ]
	for name := range members {
		ok = ok && slices.Contains(names, name)
	}
	if !ok {
		return nil, false
	}
	o := oracleReader{members: members, ok: true}
	m := o.message(typ)
	return m, o.ok
}

// message returns the message of type typ.
func (o *oracleReader) message(typ string) Message {
	switch typ {
	case "connect":
		user := o.text("user", 1, 256, true)
		o.ok = o.ok && !strings.ContainsFunc(user, func(r rune) bool { return r < ' ' || r == 0x7f })
		password := secret.New(o.text("password", 1, 1024, false))
		return Connect{Login: Login{User: user, Password: password, Key: o.base64("key", false)}, Size: o.size()}
	case "answers":
		return Answers{Values: o.answers()}
	case "signature":
		return Signature{ID: o.id(), Blob: o.base64("signature", true)}
	case "refusal":
		return Refusal{ID: o.id()}
	}
	return Resize{Size: o.size()}
}

// text returns the string member name of minBytes to maxBytes bytes.
func (o *oracleReader) text(name string, minBytes, maxBytes int, required bool) string {
	raw, present := o.members[name]
	if !present {
		o.ok = o.ok && !required
		return ""
	}
	var s string
	if raw.Kind() != '"' || json.Unmarshal(raw, &s) != nil || len(s) < minBytes || len(s) > maxBytes {
		o.ok = false
	}
	return s
}

// base64 returns the bytes of the canonical base64 member name.
func (o *oracleReader) base64(name string, required bool) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	s := o.text(name, 1, 4096, required)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || strings.Trim(s, alphabet) != "" || base64.StdEncoding.EncodeToString(b) != s {
		o.ok = false
	}
	if len(b) == 0 {
		return nil
	}
	return b
}

// digits returns the member name when it is written with digits only and no leading
// zero.
func (o *oracleReader) digits(name string) string {
	raw := string(o.members[name])
	if raw == "" || strings.Trim(raw, "0123456789") != "" || raw[0] == '0' {
		o.ok = false
	}
	return raw
}

// id returns the id member.
func (o *oracleReader) id() uint32 {
	v, err := strconv.ParseUint(o.digits("id"), 10, 32)
	o.ok = o.ok && err == nil
	return uint32(v)
}

// cells returns the size member name.
func (o *oracleReader) cells(name string) int {
	v, err := strconv.Atoi(o.digits(name))
	o.ok = o.ok && err == nil && v <= 999
	return v
}

// size returns the size members.
func (o *oracleReader) size() Size {
	return Size{Cols: o.cells("cols"), Rows: o.cells("rows")}
}

// answers returns the answers member.
func (o *oracleReader) answers() []secret.Value {
	var answers []string
	if json.Unmarshal(o.members["answers"], &answers) != nil || answers == nil || len(answers) > 16 {
		o.ok = false
	}
	values := make([]secret.Value, 0, len(answers))
	for _, a := range answers {
		o.ok = o.ok && len(a) <= 1024
		values = append(values, secret.New(a))
	}
	return values
}

func FuzzDecode(f *testing.F) {
	c := loadCorpus(f)
	for i := range c.Page {
		f.Add(c.Page[i].data())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		want, valid := oracle(data)
		got, err := Decode(data)
		if valid != (err == nil) {
			t.Fatalf("Decode(%q) error = %v, oracle valid = %t", data, err, valid)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("Decode(%q) error = %v, want ErrInvalidMessage", data, err)
			}
			return
		}
		if g, w := describe(got), describe(want); g != w {
			t.Fatalf("Decode(%q) = %s, oracle %s", data, g, w)
		}
	})
}
