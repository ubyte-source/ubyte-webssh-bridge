// Package protocol holds the messages between the page and the bridge. Binary frames
// carry terminal bytes; a text frame carries one JSON object, a control message, of at
// most MaxMessageBytes. Decode reads a text frame of the page into its Message and
// refuses with ErrInvalidMessage a member not listed, a missing one, a wrong JSON kind,
// a value past its bound, invalid UTF-8, a repeated name and nesting past two levels;
// its errors name the member and the rule, never a value, and the Message holds no
// reference to the frame. The Encode functions write the bridge's messages, each
// invalid UTF-8 byte of a device's text as U+FFFD, and cut each text to the bound the
// page applies, counted after that. CloseCode names the codes the bridge closes a
// WebSocket with, each with its fixed Reason. The package keeps no state, so concurrent
// calls are safe.
package protocol
