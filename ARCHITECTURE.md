# Ubyte WebSSH Bridge: architecture

`ubyte-webssh-bridge` serves a terminal page and a WebSocket on one HTTPS port and carries each
session over SSH to one target: the target it is configured with, or the target that a reverse proxy
in front of it picks and writes into the path. [README.md](README.md) states its contracts: the
routes, the messages and the close codes, the records, the configuration and the image;
[SECURITY.md](SECURITY.md) states the threat model and the limits. This file describes the packages,
the start, the flow of a session, the agent, the goroutines, the limits, the stop and the choices
behind them. The toolchain is Go 1.27.4, pinned by the `go` line of `go.mod` and by the build stage
of `Dockerfile`; the workflows read `go.mod`.

## Packages

| Layer | Package | Responsibility |
|-------|---------|----------------|
| 0 | `frontend` | The page, embedded in the binary. |
| 0 | `internal/config` | Every setting: the defaults, the variables, the flags, the rules among settings, the target grammar and the TLS pair. |
| 0 | `internal/protocol` | The messages between the page and the bridge, and the close codes. |
| 1 | `internal/sshclient` | The SSH leg: dial, algorithms, host key, the page's signer, the login methods, the shell. |
| 2 | `internal/session` | One page over one WebSocket: the states, the terminal bytes, the keepalive, the close code. |
| 3 | `internal/server` | HTTPS: TLS, routes, headers, files, the client address, origin, rate, caps, the stop. |
| 4 | `cmd/ubyte-webssh-bridge` | The binary: the start, the records, the stop, `-health` and `-version`. |

The production code of a package imports only packages of lower layers. The depguard rules of
`.golangci.yml` hold the layers and four more boundaries: only `internal/server` and
`internal/session` import `github.com/coder/websocket`, only `internal/sshclient` imports
`golang.org/x/crypto`, only `internal/protocol`, `internal/sshclient` and `internal/session` import
`github.com/ubyte-source/go-authware/v2`, whose `secret.Value` holds the password and the answers,
and only `internal/protocol` imports `github.com/ubyte-source/go-jsonfast`. No production code
imports `unsafe`.

**`frontend`** embeds `frontend/public` with `//go:embed public` and hands it out as `Files()`,
whose directory `Root` holds the page. The page is plain static files with absolute paths, the same
whether the bridge serves them or a web server copies the directory: `index.html` with its
Content-Security-Policy meta element, the style sheets, and ES modules of one class each, nested as
static members of `UTerminal`:

```text
UTerminal              terminal.js        xterm, fit, links, font, title, views
├─ UWebSocket          websocket.js       one WebSocket: messages, input frames, close texts
├─ UAuthentication     authentication.js  the login flow
│   ├─ UElement        authentication.js  the card
│   ├─ UKeyZone        authentication.js  drop, click and paste of a key; the key chip; Forget
│   ├─ UChallenge      authentication.js  keyboard-interactive prompts
│   └─ UAgent          agent.js           the CryptoKeys, the signing policy, the signatures
│       └─ UKey        key.js             formats, decryption, import, blob, fingerprint
│           ├─ UWire   wire.js            SSH wire reader and writer, base64
│           ├─ UDer    der.js             DER reader, the PKCS #8 wrapper
│           └─ UBcrypt bcrypt.js          Blowfish and bcrypt_pbkdf
├─ UGesture            gesture.js         touch gestures
├─ UKeyBar             keybar.js          extended keys, sticky modifiers
└─ UStorage            storage.js         the font size in localStorage
UHandler               handler.js         event delegation for every class that owns elements
```

`main.js` mounts a `UTerminal` on the body, and no other module touches `document` or `window` when
it is imported. A class builds its elements lazily in `getX()` getters and receives their events
through `UHandler.handleEvent`, which finds the element's `data-handle-event` with
`Element.closest()` and calls the method it names. Nothing hangs on `window`, and no file holds an
inline script or style. xterm 6.0.0 and its fit and web-links add-ons sit in the `lib/` directories,
copied byte for byte from the npm packages of `package-lock.json`.

**`internal/config`** is the single source of every setting. Its table holds the fourteen settings,
each with its flag, its `UWSB_` variable, its default and its range or grammar; `Load` reads the
three layers, checks every value and the rules among settings, loads the TLS pair once, and returns
the `Config` or the problems it found joined, each wrapping `ErrInvalidConfig` and naming its flag
and its variable, or the position of an argument of the command line. `JoinTarget` gives a target
its one spelling, the canonical IP (an IPv4-mapped address as IPv4 without its zone, any other zone
as given) or the lower-case name without a trailing dot, and the port without its leading zeros,
and serves both the pinned target and the path of a request. No other package reads the environment
or holds a default.

**`internal/protocol`** holds the messages. `Decode` reads a text frame of the page with go-jsonfast
into a `Connect`, `Answers`, `Signature`, `Refusal` or `Resize`; it refuses a member not listed, a
missing one, a repeated name, invalid UTF-8, nesting past 2 and every value of the wrong JSON kind
or outside its bound, with an error that names the member and never the value, and it keeps no
reference to the frame. The password and the answers become `secret.Value`, which fmt, slog and JSON
write as `***`. The `Encode` functions write the bridge's `banner`, `challenge`, `sign`, `ready` and
`exit` with go-jsonfast's Builder, a byte of invalid UTF-8 from the device as U+FFFD, and cut each
text of the device at a character to the bound the page applies, counted after that replacement.
`CloseCode` names every close code with its fixed reason, and `MaxMessageBytes`, 65536, is the
largest message the bridge reads.

**`internal/sshclient`** is the SSH leg. `Dial` connects within `-ssh-connect-timeout` and logs in
under the one deadline of `-ssh-login-timeout`: the algorithms of x/crypto, its secure ones first,
the host-key callback, the signer that asks the page, keyboard-interactive and password. `Page` is
the user behind the WebSocket as the SSH leg sees it: `HostKey` receives the host key of the first
key exchange, and `Sign`, `Answer` and `Banner` wait for the page within the login's context. A
`Client` opens a `Shell` on a PTY of terminal type `xterm`, which writes the page's input to the
shell, changes the window size and waits for the exit. Every error wraps one sentinel,
`ErrUnreachable`, `ErrHandshake`, `ErrAuthFailed`, `ErrLoginTimeout`, `ErrShellRefused`,
`ErrTargetLost` or `ErrInvalidKey`, for callers to branch on with `errors.Is`.

**`internal/session`** serves one page over one WebSocket. `Run` holds the state machine of a
session, implements `sshclient.Page` over the WebSocket, carries the terminal bytes both ways, pings
the page, picks the close code from the sentinel that ends the session, writes the session's
records, and returns once every goroutine it started has ended. The output writer and the input
forwarder are the hot path, each with an exact allocation count.

**`internal/server`** is the HTTPS server: the TLS configuration, the bounds of `http.Server`, the
routes, the policy headers, the files of `frontend.Files()`, the client address, the WebSocket
handler with its origin, rate and cap checks, the lifetime of the sessions and the stop.

**`cmd/ubyte-webssh-bridge`** is the binary. `run` loads the configuration, answers `-h`, `-version`
and `-health`, builds the logger, writes the start records, listens, serves until the first SIGINT
or SIGTERM and returns the exit status; `main` calls `run` and `os.Exit` and nothing more.

## Start

1. `config.Load` sets the defaults, then every `UWSB_` variable with a value, then every flag given
   on the command line, each over the one below, and reads no flag after an argument that is not a
   flag, an unknown flag, a flag without its value or a malformed flag. It checks each value as its
   variable or flag gives it, then, once `-ssh-target` parses, the rules among settings: a
   `-conn-max-per-host` set beside `-ssh-target`, or above `-conn-max-total`, and a listen address
   beyond loopback without `-ssh-target`, which would make the bridge an open relay. It then loads
   the TLS pair with `tls.LoadX509KeyPair`. It returns the problems it found at once, or `ErrHelp`
   (the usage is written, status 0) or `ErrVersionRequested` (`<version> (go=<release>)`, status 0);
   a refused configuration writes its record `invalid configuration` to stderr and ends the process
   with status 2. A usage, a version line or that record that cannot be written ends the process
   with status 1 instead.
2. `run` builds the one `slog.JSONHandler` on stdout, at info or at debug with `-server-debug`, logs
   `starting ubyte-webssh-bridge` with the route, the target and the caps, and logs `unread
   variable` at warn for each `UWSB_` variable with a value that no setting reads.
3. `net.ListenConfig.Listen` opens the TCP listener on `-server-address`; a failure logs `listen
   failed` and ends the process with status 1.
4. `server.New` builds the server and `Serve` serves TLS on the listener until the context of the
   run ends, which the first SIGINT or SIGTERM does; it logs `serving` with the listener's address.

`-health` loads the configuration in the same way and, in place of steps 2 to 4, dials the listen
address over TCP within 4 s, without a TLS handshake: status 0 when it connects, 1 otherwise.

The server holds one `http.ServeMux`. With `-ssh-target` set, `GET /ws` goes to the WebSocket
handler with that target; with it empty, `GET /ws/{host}/{port}` goes there with `config.JoinTarget`
of the two path values, 400 on an invalid target. `GET /` serves `index.html`, every other path the
regular file of the page it names, and 404 when none matches; a method other than GET and HEAD is
answered 405 with `Allow`. A middleware sets the policy headers on every response: the
Content-Security-Policy, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
`Cross-Origin-Resource-Policy` and `Cache-Control: no-cache`. The `http.Server` reads the request
headers within `-ws-handshake-timeout`, writes a file within 60 s, keeps an idle connection 120 s
and takes at most 20480 bytes of request line and headers over HTTP/1.1, its 16384 and net/http's
4096 of read slack; it logs TLS handshake errors at debug, and its base context is the server's
lifetime context, from which every request, and so every session, derives.

## Flow of a session

The WebSocket handler finds the client address and the TCP peer (see [Limits](#limits)), then, in
this order, refuses a request:

1. without an `Origin` header, 403;
2. with an invalid target in its path, on the path route, 400;
3. that `websocket.Accept` refuses: an `Origin` whose host differs from `Host` (403), or a request
   that is no upgrade; compression stays off, so no secret is compressed beside data of the page;
4. whose client has spent its rate of new sessions, or is a new client address the rate bound has
   no room for: the WebSocket closes with 4008;
5. that finds a cap full: the WebSocket closes with 4007.

Each refusal logs `refused` at debug with its reason. The handler then runs `session.Run` and, once
it returns, releases the cap slots. `Run` moves the session through these states:

| State | Entered when | Page frames accepted | Leaves to |
|-------|--------------|----------------------|-----------|
| `waiting` | the WebSocket is accepted | `connect` | `dialing`; 1008 on anything else or on no connect within `-ws-handshake-timeout` |
| `dialing` | `connect` decoded | `resize` | `exchanging` once TCP connects, or 4003 |
| `exchanging` | TCP connected | `resize` | `authenticating` once the host key is accepted, 4004 or 4005 |
| `authenticating` | the first key exchange completed | `signature` or `refusal` for the pending `sign`, `answers` for the pending `challenge`, `resize` | `opening`, or 4002, 4005, 4010 |
| `opening` | authenticated | `resize` | `active` once the shell starts, or 4005, 4006 |
| `active` | the shell started and `ready` written | binary frames, `resize` | `ended` |
| `ended` | an exit, a failure, the page gone or the stop | none | closed |

A frame the state does not accept, a `signature` or `refusal` with another `id`, or `answers` of the
wrong count close the session with 1008. The session reads each message into one buffer of 65536
bytes and overwrites it once `protocol.Decode` has copied what it needs, so the bytes of a password
leave the buffer as soon as they are decoded.

`connect` carries the user name, the password when one is typed, the public key when one is loaded,
and the terminal size. The session passes the login to `sshclient.Dial` with itself as the `Page`.
`Dial` connects, and x/crypto exchanges keys and calls the host-key callback, which accepts the key
of the first exchange without asking the page, keeps its blob for the connection and reports its
type and SHA256 fingerprint through `Page.HostKey`, for a certificate those of the key it certifies;
a later key exchange of the same connection passes only with the same key. x/crypto then tries the
methods in OpenSSH's order: `publickey` with the page's key (see [The agent](#the-agent)),
`keyboard-interactive`, `password`, three tries each for the last two. A banner of the device
reaches the page as `banner`. A keyboard-interactive round reaches it as `challenge`, and its
`answers` come back, but for the first round that holds one prompt without echo, which the typed
password answers once per connection. The password method takes the typed password first, then asks
through a one-prompt `challenge`. Every wait on the page runs under the login's deadline and ends at
once when the page goes away or the bridge stops.

The login methods reach the typed password only through one pointer, which `Dial` zeroes as soon as
the handshake returns, since x/crypto keeps its configuration, the methods included, for the life of
the connection. When `Dial` returns, the session drops its `connect` and keeps no answer. It logs
`session authenticated` with the user, the method, the fingerprint of the page's key for `publickey`
and the host key's type and fingerprint.

The session then opens the shell: an SSH session channel, a PTY of terminal type `xterm` with UTF-8
at the size the page last sent, and the shell, still under the login's deadline, which a page that
goes away or the stop ends at once; then it writes `ready`, and a size the page sent meanwhile
reaches the shell. Binary frames of the page go to the shell's input; the shell's output and error
streams go to the output writer, which sends each chunk, at most 32768 bytes, as one binary frame;
`resize` changes the window size. When the shell ends, the session writes `exit`, with the exit
status or the signal the device sent, and closes with 1000; a shell that ends without either gives
an `exit` without them, whether the device then closes or resets the connection. Any other end maps
the sentinel that caused it to its close code: `ErrAuthFailed` 4002, `ErrUnreachable` 4003,
`ErrHandshake` 4004, `ErrLoginTimeout` 4005, `ErrShellRefused` 4006, `ErrTargetLost` 4010 (the
bridge ended the connection, at input the device does not take or at a rekey that presents another
host key, or the connection failed by a timeout or another error that is neither its close nor a
reset), an invalid frame or `ErrInvalidKey` 1008, the stop 1001, a page that stops answering 4009, a
message past 65536 bytes, which coder/websocket closes, 1009, and any other page gone 1006. A
session that authenticated logs `session ended`; one that did not logs `session failed`, at warn for
4003 and 4004, at debug otherwise.

The session pings the page every 30 s and waits 90 s for the pong. A round is skipped while the
input forwarder is blocked writing to the shell, since the page has just sent data and the device is
slow to read it; a write the device does not take within 5 minutes closes the SSH connection, which
ends the write however frozen the device is, and the session with 4010, so the skip lasts at most
that long. A frame the bridge writes before the end, a message or terminal output, that the page
does not take within 90 s ends the session with 4009. Behind `exit` the session pings once more and
closes only once that pong came, so a page slow to read the last output and the exit still takes
them, which coder/websocket's 5 s wait for the page's close frame would cut short: a close while the
page types resets the connection and drops what the page has not read. The wait ends at 90 s, or at
once when the page goes or the server stops, and the session closes with 1000 all the same.

## The agent

The page is an SSH agent of one key. It reads the private key in the browser, imports it as
non-extractable WebCrypto keys, and announces its public blob in `connect`; the bridge never holds
private material.

When `connect` carries a key, `Dial` first parses it and refuses anything but an Ed25519 key, an
ECDSA key on P-256, P-384 or P-521, or an RSA key of 1024 to 16384 bits, with `ErrInvalidKey`. The
page's signer offers the key to x/crypto: for an RSA key the algorithms rsa-sha2-512, rsa-sha2-256
and ssh-rsa, in that order, and for any other key its own type. x/crypto picks the first of them the
device lists in its `server-sig-algs`, or `ssh-rsa` for an RSA key when the device lists none, and
sends the key without a signature first, so the page is asked only once the device answers that it
accepts the key. The bridge then sends `sign` with an `id`, the bytes to sign and the agent flags of
the algorithm: 0, 2 for rsa-sha2-256, 4 for rsa-sha2-512.

The page signs only when every rule holds, and answers `refusal` otherwise:

1. the request arrives on the WebSocket the user opened with Connect or Reconnect, before `ready`;
2. it is the first signature of that WebSocket;
3. the data is exactly an SSH `publickey` userauth request: a session identifier of 20, 32, 48 or 64
   bytes, byte 50, the user, `ssh-connection`, `publickey`, true, the algorithm and the key blob,
   and nothing after;
4. the user is the user name sent in `connect`;
5. the key blob is the loaded key's;
6. the algorithm and the flags agree with the key.

These rules bound what a bridge that is not the user's can obtain from the page: one login signature
per Connect, for the user typed, over a session identifier that belongs to one SSH connection.

The bridge, in turn, verifies the answer before x/crypto sends it: it must read as one SSH signature
with nothing after it, its format must be the algorithm x/crypto asked for, and it must verify under
the announced key for the bytes the bridge sent. A refusal or an answer that fails the check fails
the `publickey` method in the bridge, and the login moves to keyboard-interactive: no bytes of the
page reach the device as a signature unless they are a valid signature over exactly the request of
that connection.

## Goroutines

| Goroutines | Count | End |
|------------|-------|-----|
| the accept loop of the server | 1 | the stop closes the listener |
| net/http's, for each TCP connection: TLS, the requests, and for a WebSocket the handler that runs `session.Run` | one per connection | the response, the idle timeout, or the return of `Run` |
| the reader of a session: every frame of the page, the pongs, the control messages, and the forward of binary frames to the shell; once the session ended, the drop of the page's frames, since its close frame comes behind its input | one per session | the end of the WebSocket |
| the pinger of a session | one per session | the end of the session's context |
| the ping behind `exit` and the wait for its pong | one per session whose shell exited | the pong, 90 s, or the close of the WebSocket |
| the waiter of a session's shell | one per active session | the shell's exit, or the end of the SSH connection |
| x/crypto's, for each SSH connection: its transport and its key exchanges, and the dispatch of its channels | its own | the close of the SSH connection |
| x/crypto's copiers of a shell: its output and its error stream into the output writer | 2 per shell | the close of the channel |
| the functions of `context.AfterFunc`: they close the SSH connection of a blocked login, opening of the shell or write | one when its context ends | the close |

The session's context derives from the request's, so the server's lifetime context, the page's close
and the session's own end cancel it, and every goroutine of the session ends through it, the reader
with the WebSocket that `Run` then closes: the close completes, or ends past coder/websocket's own
bound of 5 s to write the close frame and 5 s to wait for the page's. `Run` returns only after the
goroutines it started have ended, and closes the SSH connection, which ends x/crypto's.

## Limits

**Concurrent sessions** (`caps.go`) take no lock, since an unauthenticated client reaches them. One
`atomic.Int64` counts the sessions of the process, reserved by a compare-and-swap loop while it is
below `-conn-max-total`; with `-ssh-target` set, that cap is the target's and the reservation is the
whole grant. On the path route, a `sync.Map` holds one slot per target with a live session: the
handler loads or stores the target's slot and adds one by compare-and-swap while it is below
`-conn-max-per-host`, retrying on a lost swap or on a retired slot, and gives the process
reservation back when the slot is full. A release subtracts one, and the release that reaches zero
retires the slot with a swap to -1 and deletes it, so the map holds at most `-conn-max-total` slots.

**New sessions per client address** (`rate.go`) follow GCRA. The emission interval is
`-rate-interval` divided by `-rate-burst`, so a client opens `-rate-burst` sessions at once and then
one per interval; each key holds its theoretical arrival time in an `atomic.Int64`, advanced by
compare-and-swap. The key is the client's IPv4 address or the /64 of its IPv6 address. At most 65536
keys are held: when a new key would pass the bound, one caller sweeps the map and retires every key
whose bucket is full again; when the sweep frees no room, the new key is refused with 4008, and
known keys keep working.

**The client address** is the TCP peer, unless `-server-trusted-proxies` lists the peer. Then the
bridge walks `X-Forwarded-For`, every header line in order and each split at commas, from the right
through trusted addresses, and the first address that is not trusted is the client; an entry that is
not an IP address stops the walk at the last address read, and when every entry is trusted the
client is the leftmost. Without `X-Forwarded-For`, an `X-Real-IP` that parses as an IP address is
the client. `Forwarded` is not read. Records that carry `client` carry `peer` too when the two
differ.

**Every wait** has its bound: the request headers and the connect message `-ws-handshake-timeout`;
the TCP connect `-ssh-connect-timeout`; the login and the opening of the shell, the page's answers
and signatures included, `-ssh-login-timeout`; the pong 90 s; a frame to the page 90 s; a write to
the shell 5 minutes; the close of the WebSocket coder/websocket's own, 5 s to write the close frame
and 5 s to wait for the page's; a file response 60 s; an idle HTTP connection 120 s; the stop
`-server-shutdown-timeout`. Every message of the page is bounded by size, by nesting and member by
member. SECURITY.md holds the table of every limit and the tests that pin it.

## Stop

When the context of `Serve` ends:

1. the server cancels its lifetime context, so every session closes its SSH connection and its
   WebSocket with 1001 `server shutting down`;
2. `http.Server.Shutdown` closes the listener and the idle connections, under a budget of
   `-server-shutdown-timeout` that the ended context does not cut short;
3. `Serve` waits for the sessions until the budget ends; past it, it closes every remaining
   connection with `http.Server.Close`, logs `stop outlasted the budget` at error, and returns.

The process logs `stopping` with its cause on the first signal and exits with status 0. A failure of
the server before the stop logs `serve failed` and ends the process with status 1.

## Design

- **No open relay**: a client names a target only on the path route, and the bridge starts on the
  path route only when it listens on a loopback IP literal, behind the proxy that writes the target.
  Anywhere else, one target is pinned and `/ws` reaches it and nothing else.
- **The page as the agent**: the private key and its passphrase never leave the browser. The bridge
  needs one signature per login, so the page answers sign requests under a policy that a bridge
  cannot widen, and the bridge checks every signature it relays.
- **The host key of the first exchange**: the bridge accepts the device's host key without asking,
  pins it for the connection, and logs its fingerprint; the page asks nothing about host keys and
  stores none, so a session works on any network the user moves to.
- **Lock-free caps and rate**: the checks a client reaches before it logs in take no exclusive lock;
  compare-and-swap on atomics, with retired slots and cells, keeps the counts exact under any
  interleaving and the maps bounded.
- **No certificate made at start**: the TLS pair always comes from two PEM files. A pair made at
  every boot would change its fingerprint at every restart and teach users to click through the
  browser's warning.
- **No SSH keepalive**: some old devices drop a connection on an unknown global request, so the
  bridge sends none; the TCP keep-alive of the dialer finds a device that vanishes.
