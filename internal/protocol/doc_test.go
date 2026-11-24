package protocol

import (
	"encoding/json"
	"os"
	"testing"
)

// corpusPath is the message corpus the page's tests read too.
const corpusPath = "../../frontend/test/fixtures/protocol.json"

// pageFields are the members of a valid page frame, binary members in base64.
type pageFields struct {
	Password  *string  `json:"password"`
	Type      string   `json:"type"`
	User      string   `json:"user"`
	Key       string   `json:"key"`
	Signature string   `json:"signature"`
	Answers   []string `json:"answers"`
	Cols      int      `json:"cols"`
	Rows      int      `json:"rows"`
	ID        uint32   `json:"id"`
}

// pageFrame is one page frame of the corpus with its verdict and, when valid, its
// fields.
type pageFrame struct {
	Frame       *string    `json:"frame"`
	Name        string     `json:"name"`
	FrameBase64 []byte     `json:"frame_base64"`
	Fields      pageFields `json:"fields"`
	Valid       bool       `json:"valid"`
}

// data returns the bytes of the frame.
func (p *pageFrame) data() []byte {
	if p.Frame == nil {
		return p.FrameBase64
	}
	return []byte(*p.Frame)
}

// promptFields are the members of one prompt of a challenge.
type promptFields struct {
	Text string `json:"text"`
	Echo bool   `json:"echo"`
}

// bridgeFields are the members of a bridge frame, binary members in base64.
type bridgeFields struct {
	Status      *int           `json:"status"`
	Type        string         `json:"type"`
	Text        string         `json:"text"`
	Name        string         `json:"name"`
	Instruction string         `json:"instruction"`
	Data        string         `json:"data"`
	Signal      string         `json:"signal"`
	Prompts     []promptFields `json:"prompts"`
	ID          uint32         `json:"id"`
	Flags       uint32         `json:"flags"`
}

// bridgeFrame is one bridge frame of the corpus with its fields.
type bridgeFrame struct {
	Name   string       `json:"name"`
	Frame  string       `json:"frame"`
	Fields bridgeFields `json:"fields"`
}

// messageCorpus is protocol.json.
type messageCorpus struct {
	Page   []pageFrame   `json:"page"`
	Bridge []bridgeFrame `json:"bridge"`
}

// loadCorpus reads the message corpus.
func loadCorpus(tb testing.TB) messageCorpus {
	tb.Helper()
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		tb.Fatalf("read corpus: %v", err)
	}
	var c messageCorpus
	if err := json.Unmarshal(data, &c); err != nil {
		tb.Fatalf("decode corpus: %v", err)
	}
	return c
}
