// Command ubyte-webssh-bridge is a jump host in the browser: one HTTPS port serves the
// page and the WebSocket over which each session reaches an SSH device, the target
// pinned by -ssh-target, or named by the path on a loopback listener behind a proxy
// that picks it; the private key stays in the browser, which signs as the user's
// agent. The defaults, then the UWSB_ variables, then the flags given on the command
// line set the configuration, each over the one before. The first SIGINT or SIGTERM
// closes every session and stops within -server-shutdown-timeout. -health dials the
// listen address, -version prints the version and -h the usage. Exit status 0 reports
// a stop on a signal, the usage, the version and a probe that connects; 1 a failure at
// run time and a probe that does not; 2 a configuration or a command line to fix.
package main
