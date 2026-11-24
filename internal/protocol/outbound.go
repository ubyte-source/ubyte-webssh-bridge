package protocol

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/ubyte-source/go-jsonfast"
)

// The bounds of the texts the bridge sends, in bytes of UTF-8 once each invalid byte is
// U+FFFD, as the page measures them; a text past its bound is cut at a rune boundary.
const (
	maxBannerBytes = 16384
	maxTextBytes   = 4096
	maxPromptBytes = 1024
	maxSignalBytes = 32
)

// EncodeBanner returns the banner message of text, cut to maxBannerBytes at a rune
// boundary.
func EncodeBanner(text string) []byte {
	return jsonfast.Build(func(b *jsonfast.Builder) {
		begin(b, "banner")
		b.AddStringField(nameText, cut(text, maxBannerBytes))
		b.EndObject()
	})
}

// EncodeChallenge returns the challenge message of c, its name and instruction cut to
// maxTextBytes and each prompt to maxPromptBytes at a rune boundary.
func EncodeChallenge(c Challenge) []byte {
	return jsonfast.Build(func(b *jsonfast.Builder) {
		begin(b, "challenge")
		b.AddStringField(nameName, cut(c.Name, maxTextBytes))
		b.AddStringField(nameInstruction, cut(c.Instruction, maxTextBytes))
		b.BeginArrayField(namePrompts)
		for _, p := range c.Prompts {
			b.BeginObjectElement()
			b.AddStringField(nameText, cut(p.Text, maxPromptBytes))
			b.AddBoolField(nameEcho, p.Echo)
			b.EndObject()
		}
		b.EndArray()
		b.EndObject()
	})
}

// EncodeSign returns the sign message that asks the page, under id, to sign data with
// the agent flags.
func EncodeSign(id uint32, data []byte, flags uint32) []byte {
	return jsonfast.Build(func(b *jsonfast.Builder) {
		begin(b, "sign")
		b.AddUint64Field(nameID, uint64(id))
		b.AddStringField(nameData, base64.StdEncoding.EncodeToString(data))
		b.AddUint64Field(nameFlags, uint64(flags))
		b.EndObject()
	})
}

// EncodeReady returns the ready message: the shell is started.
func EncodeReady() []byte {
	return jsonfast.Build(func(b *jsonfast.Builder) {
		begin(b, "ready")
		b.EndObject()
	})
}

// EncodeExit returns the exit message of e, its signal name cut to maxSignalBytes at
// a rune boundary.
func EncodeExit(e Exit) []byte {
	return jsonfast.Build(func(b *jsonfast.Builder) {
		begin(b, "exit")
		if e.HasStatus {
			b.AddIntField(nameStatus, e.Status)
		}
		if e.Signal != "" {
			b.AddStringField(nameSignal, cut(e.Signal, maxSignalBytes))
		}
		b.EndObject()
	})
}

// begin opens a message of the type named typ.
func begin(b *jsonfast.Builder, typ string) {
	b.BeginObject()
	b.AddStringField(nameType, typ)
}

// cut returns the longest prefix of s that ends at a rune boundary and is at most n
// bytes of UTF-8 once each invalid byte is U+FFFD, as go-jsonfast writes it.
func cut(s string, n int) string {
	size := 0
	for i, r := range s {
		if size += utf8.RuneLen(r); size > n {
			return s[:i]
		}
	}
	return s
}
