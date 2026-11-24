package protocol

import (
	"encoding/base64"
	"errors"
	"math"
	"strconv"

	"github.com/ubyte-source/go-authware/v2/secret"
	"github.com/ubyte-source/go-jsonfast"
)

// errPrefix starts the text of every error the package returns.
const errPrefix = "protocol: "

// ErrInvalidMessage reports a text frame of the page that is no valid message.
var ErrInvalidMessage = errors.New(errPrefix + "invalid message")

// Kind names the type of a control message of the page.
type Kind uint8

// The kinds of the page's control messages, one per message type.
const (
	KindConnect Kind = iota + 1
	KindAnswers
	KindSignature
	KindRefusal
	KindResize
)

// Message is one control message of the page: Connect, Answers, Signature, Refusal or
// Resize.
type Message interface {
	// Kind returns the type of the message.
	Kind() Kind
}

// Connect opens a session: the login and the size of the terminal.
type Connect struct {
	Login Login
	Size  Size
}

// Kind returns KindConnect.
func (Connect) Kind() Kind { return KindConnect }

// Answers holds the user's answers to the pending challenge, one per prompt.
type Answers struct{ Values []secret.Value }

// Kind returns KindAnswers.
func (Answers) Kind() Kind { return KindAnswers }

// Signature answers the pending sign request with the page's signature.
type Signature struct {
	Blob []byte // SSH wire signature: string format, string blob
	ID   uint32
}

// Kind returns KindSignature.
func (Signature) Kind() Kind { return KindSignature }

// Refusal declines the pending sign request.
type Refusal struct{ ID uint32 }

// Kind returns KindRefusal.
func (Refusal) Kind() Kind { return KindRefusal }

// Resize carries the size the terminal takes.
type Resize struct{ Size Size }

// Kind returns KindResize.
func (Resize) Kind() Kind { return KindResize }

// The bounds of the page's messages.
const (
	maxDepth         = 2
	maxUserBytes     = 256
	maxPasswordBytes = 1024
	maxAnswerBytes   = 1024
	maxAnswers       = 16
	maxBase64Chars   = 4096
	maxCells         = 999
	del              = 0x7f
)

// The rules a frame breaks, as its errors state them.
const (
	ruleJSON     = "is not one JSON object of valid UTF-8, unique names and nesting at most 2"
	ruleUnknown  = "holds a member not listed"
	ruleType     = "is not a type of the page"
	ruleTaken    = "is not a member of this type"
	ruleMissing  = "is missing"
	ruleString   = "is not a string"
	ruleControl  = "holds a control byte"
	ruleBase64   = "is not standard base64 with padding"
	ruleID       = "is not an integer from 1 to 4294967295"
	ruleCells    = "is not an integer from 1 to 999"
	ruleStrings  = "is not an array of strings"
	ruleAnswers  = "holds more than 16 answers"
	ruleAnswer   = "holds an answer of more than 1024 bytes"
	memberFrame  = "message"
	bytesBetween = " bytes long"
)

// invalid is an error of Decode: the member that breaks a rule, and the rule.
type invalid struct {
	member string
	rule   string
}

// Error returns the text of e, which holds no value of the frame.
func (e invalid) Error() string {
	return ErrInvalidMessage.Error() + ": " + e.member + " " + e.rule
}

// Unwrap returns ErrInvalidMessage.
func (invalid) Unwrap() error { return ErrInvalidMessage }

// member indexes the members of the page's messages.
type member uint8

// The members of the page's messages, then the count of them.
const (
	memberType member = iota
	memberUser
	memberPassword
	memberKey
	memberCols
	memberRows
	memberAnswers
	memberID
	memberSignature
	memberCount
)

// unknownBit marks, in a reader's present set, a member not listed.
const unknownBit = 1 << memberCount

// name returns the JSON name of m, one of the members before memberCount.
func (m member) name() string {
	switch m {
	case memberType:
		return nameType
	case memberUser:
		return nameUser
	case memberPassword:
		return namePassword
	case memberKey:
		return nameKey
	case memberCols:
		return nameCols
	case memberRows:
		return nameRows
	case memberAnswers:
		return nameAnswers
	case memberID:
		return nameID
	default:
		return nameSignature
	}
}

// bit returns the bit of m in a set of members.
func (m member) bit() uint16 { return 1 << m }

// name returns the JSON type of the messages of k, one of the kinds.
func (k Kind) name() string {
	switch k {
	case KindConnect:
		return "connect"
	case KindAnswers:
		return nameAnswers
	case KindSignature:
		return nameSignature
	case KindRefusal:
		return "refusal"
	default:
		return "resize"
	}
}

// members returns the set of members a message of k, one of the kinds, holds, the
// optional ones of a connect included.
func (k Kind) members() uint16 {
	size := memberCols.bit() | memberRows.bit()
	switch k {
	case KindConnect:
		return memberUser.bit() | memberPassword.bit() | memberKey.bit() | size | memberType.bit()
	case KindAnswers:
		return memberAnswers.bit() | memberType.bit()
	case KindSignature:
		return memberID.bit() | memberSignature.bit() | memberType.bit()
	case KindRefusal:
		return memberID.bit() | memberType.bit()
	default:
		return size | memberType.bit()
	}
}

// optional is the set of members a message may leave out.
const optional = 1<<memberPassword | 1<<memberKey

// reader holds the raw values of one frame's members, nil for one absent, and the
// first rule the frame breaks, which later failures leave as it is.
type reader struct {
	err     error
	values  [memberCount][]byte
	present uint16
}

// take files the raw value of the member called name.
func (r *reader) take(name, value []byte) error {
	for m := range memberCount {
		if string(name) == m.name() {
			r.values[m] = value
			r.present |= m.bit()
			return nil
		}
	}
	r.present |= unknownBit
	return nil
}

// fail keeps the first broken rule.
func (r *reader) fail(m member, rule string) {
	if r.err == nil {
		r.err = invalid{member: m.name(), rule: rule}
	}
}

// kind returns the kind the type member names, after checking that the frame holds
// exactly the members of that kind.
func (r *reader) kind() Kind {
	if r.present&unknownBit != 0 {
		r.err = invalid{member: memberFrame, rule: ruleUnknown}
		return 0
	}
	raw := r.values[memberType]
	for k := KindConnect; k <= KindResize; k++ {
		if raw != nil && jsonfast.EqualString(raw, k.name()) {
			r.check(k.members())
			return k
		}
	}
	r.fail(memberType, ruleType)
	return 0
}

// check fails on the first member, in member order, that is present outside want or
// required by it and absent.
func (r *reader) check(want uint16) {
	for m := range memberCount {
		switch bit := m.bit(); {
		case r.present&bit != 0 && want&bit == 0:
			r.fail(m, ruleTaken)
		case r.present&bit == 0 && want&^optional&bit != 0:
			r.fail(m, ruleMissing)
		}
	}
}

// text returns the string of m of minBytes to maxBytes bytes, copied out of the frame,
// or "" when m is absent.
func (r *reader) text(m member, minBytes, maxBytes int) string {
	raw := r.values[m]
	if r.err != nil || raw == nil {
		return ""
	}
	s, ok := jsonfast.DecodeString(raw)
	switch {
	case !ok:
		r.fail(m, ruleString)
	case len(s) < minBytes || len(s) > maxBytes:
		r.fail(m, "is not "+strconv.Itoa(minBytes)+" to "+strconv.Itoa(maxBytes)+bytesBetween)
	}
	return s
}

// user returns the user name, which holds no control byte.
func (r *reader) user() string {
	s := r.text(memberUser, 1, maxUserBytes)
	for i := range len(s) {
		if s[i] < ' ' || s[i] == del {
			r.fail(memberUser, ruleControl)
		}
	}
	return s
}

// binary returns the bytes of m, whose string is canonical standard base64 of 1 to
// maxBase64Chars characters, or nil when m is absent.
func (r *reader) binary(m member) []byte {
	s := r.text(m, 1, maxBase64Chars)
	if r.err != nil || s == "" {
		return nil
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodedLen(len(b)) != len(s) {
		r.fail(m, ruleBase64)
	}
	return b
}

// id returns the identifier of a sign request, an integer from 1 to 4294967295.
func (r *reader) id() uint32 {
	v, _ := jsonfast.DecodeUint64(r.values[memberID])
	if v < 1 || v > math.MaxUint32 {
		r.fail(memberID, ruleID)
		return 0
	}
	return uint32(v)
}

// cells returns the count of character cells of m, an integer from 1 to maxCells.
func (r *reader) cells(m member) int {
	v, _ := jsonfast.DecodeUint64(r.values[m])
	if v < 1 || v > maxCells {
		r.fail(m, ruleCells)
		return 0
	}
	return int(v)
}

// size returns the size of the terminal.
func (r *reader) size() Size {
	return Size{Cols: r.cells(memberCols), Rows: r.cells(memberRows)}
}

// answers returns the answers, each copied out of the frame.
func (r *reader) answers() []secret.Value {
	if r.err != nil {
		return nil
	}
	var values []secret.Value
	err := jsonfast.IterateStringArray(r.values[memberAnswers], func(s []byte) error {
		switch {
		case len(values) == maxAnswers:
			return invalid{member: nameAnswers, rule: ruleAnswers}
		case len(s) > maxAnswerBytes:
			return invalid{member: nameAnswers, rule: ruleAnswer}
		}
		values = append(values, secret.New(string(s)))
		return nil
	})
	if errors.Is(err, jsonfast.ErrMalformed) {
		err = invalid{member: nameAnswers, rule: ruleStrings}
	}
	r.err = err
	return values
}

// Decode reads data, one text frame of the page, into its Message, or returns an
// error that wraps ErrInvalidMessage; the Message holds no reference to data.
func Decode(data []byte) (Message, error) {
	var r reader
	if jsonfast.IterateDocument(data, maxDepth, r.take) != nil {
		return nil, invalid{member: memberFrame, rule: ruleJSON}
	}
	var m Message
	switch r.kind() {
	case KindConnect:
		login := Login{User: r.user()}
		login.Password = secret.New(r.text(memberPassword, 1, maxPasswordBytes))
		login.Key = r.binary(memberKey)
		m = Connect{Login: login, Size: r.size()}
	case KindAnswers:
		m = Answers{Values: r.answers()}
	case KindSignature:
		m = Signature{ID: r.id(), Blob: r.binary(memberSignature)}
	case KindRefusal:
		m = Refusal{ID: r.id()}
	default:
		m = Resize{Size: r.size()}
	}
	if r.err != nil {
		return nil, r.err
	}
	return m, nil
}
