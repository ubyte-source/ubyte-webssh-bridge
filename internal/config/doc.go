// Package config loads the configuration of ubyte-webssh-bridge: the defaults, then
// the UWSB_ variables, then the flags given on the command line, each layer over the
// one below; an empty variable or flag value leaves the layer below in place. One
// table names every setting with its flag, its variable, its default, its parser and
// its range. Load reports every problem at once, each naming its flag and its variable
// and wrapping ErrInvalidConfig, loads the TLS pair, refuses the path route on a
// listener beyond loopback, and lists through UnreadNames the UWSB_ variables no
// setting reads, which never stop the start. JoinTarget holds the grammar of a target
// and gives each target one spelling. No zero value of a configuration type is ready
// to use: a Config comes from Load, and its methods only read it, so concurrent calls
// are safe.
package config
