package protocol

import "github.com/ubyte-source/go-authware/v2/secret"

// Login is what the user gives the device: the user name, the typed password, the
// page's public key.
type Login struct {
	Password secret.Value
	Key      []byte // SSH wire blob of the page's public key; nil without a key
	User     string
}

// MaxMessageBytes is the largest message, text or binary, the bridge reads from the
// page.
const MaxMessageBytes = 64 << 10

// Size is the size of the terminal in character cells.
type Size struct{ Cols, Rows int }

// Prompt is one question of a challenge, its answer shown as typed when Echo is set.
type Prompt struct {
	Text string
	Echo bool
}

// Challenge is one keyboard-interactive round of the device: its name, its
// instruction and its prompts.
type Challenge struct {
	Name        string
	Instruction string
	Prompts     []Prompt
}

// Exit is how the shell ended: the exit status when HasStatus is set, and the signal
// that ended it when there is one.
type Exit struct {
	Signal    string
	Status    int
	HasStatus bool
}

// The JSON names of the members of the messages and of the prompts.
const (
	nameType        = "type"
	nameUser        = "user"
	namePassword    = "password"
	nameKey         = "key"
	nameCols        = "cols"
	nameRows        = "rows"
	nameAnswers     = "answers"
	nameID          = "id"
	nameSignature   = "signature"
	nameText        = "text"
	nameName        = "name"
	nameInstruction = "instruction"
	namePrompts     = "prompts"
	nameEcho        = "echo"
	nameData        = "data"
	nameFlags       = "flags"
	nameStatus      = "status"
	nameSignal      = "signal"
)
