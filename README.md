# Ubyte WebSSH Bridge

[![Go Version](https://img.shields.io/badge/Go-1.27.4-blue.svg)](https://go.dev/)
[![Lint](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/lint.yml/badge.svg)](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/lint.yml)
[![Test](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/test.yml)
[![Security](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/security.yml/badge.svg)](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/security.yml)
[![Fuzz](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ubyte-source/ubyte-webssh-bridge/actions/workflows/fuzz.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A jump host in the browser. One HTTPS port serves a terminal page and the WebSocket behind
it, and the bridge carries each session over SSH to the one target it is configured with,
or to the target that a reverse proxy in front of it picks. The private key never leaves
the browser: the page holds it and signs for the bridge as the user's SSH agent.

## Highlights

- **The key as a browser agent**: the page reads the private key locally, keeps it as
  non-extractable WebCrypto keys and answers the bridge's sign requests as an SSH agent of
  one key: one signature per connection, of the login request for the user typed, before
  the shell starts. No file is uploaded and nothing is stored.
- **Old equipment**: the client offers x/crypto's secure algorithms first and then the
  insecure ones it still implements, signs with `ssh-rsa` for a server that announces no
  RSA-SHA2 algorithm, and logs in with keyboard-interactive and password too.
- **No host key to store or confirm**: the bridge accepts the host key of the first key
  exchange, pins it for the connection, so a rekey that presents another key ends it, and
  logs its type and fingerprint.
- **Phone and desktop**: a key bar with sticky Ctrl and Alt above the on-screen keyboard,
  flicks, a cursor drag, two-finger scroll, pinch and a long-press menu on a phone; copy on
  selection, the paste shortcuts, clickable links and font zoom on a desktop.
- **One static binary, no open relay**: TLS, the embedded page and the WebSocket in one
  process, on a distroless image; a client names the target only through a listener on
  loopback, behind the proxy that writes it.

## How it works

```text
browser                           bridge                                device
page, xterm, the key  <== wss ==>  origin, target, rate, caps  <== SSH ==>  sshd
                                   session: host key, login, PTY, shell
```

1. The page opens `wss://<host>/ws` and sends `connect`: the user name, the password when
   one is typed, the public key when one is loaded and the size of the terminal.
2. The bridge connects to the target and exchanges keys; it accepts the device's host key,
   pins it for the connection and logs its type and fingerprint.
3. It logs in: with the page's key, which the page signs for, then keyboard-interactive and
   password, each prompt answered in the page.
4. It opens a PTY of terminal type `xterm` and the shell, and sends `ready`.
5. Terminal bytes travel in binary frames both ways until the shell exits; the bridge sends
   `exit` and a ping, and closes the WebSocket with 1000 once the pong shows the page took
   every frame.

[ARCHITECTURE.md](ARCHITECTURE.md) describes the packages, the goroutines and the flow of a
session.

## Quick start

### Image

```bash
mkdir -p tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/CN=bridge.example.test" -addext "subjectAltName=DNS:bridge.example.test" \
  -keyout tls/certificate.key -out tls/certificate.crt
sudo chown 65532:65532 tls/certificate.crt tls/certificate.key
docker run -d -p 8443:8443 -v "$PWD/tls:/data:ro" -e UWSB_SSH_TARGET=192.0.2.10:22 \
  ubyte/ubyte-webssh-bridge:2.0.0
```

The image runs as uid 65532, which must be able to read both files. Open
`https://bridge.example.test:8443/`. Use a certificate the browsers trust; a self-signed one
belongs in the trust store of the browsers that use the bridge, so that nobody learns to
click through a certificate warning. To reach the sshd of the host that runs the container,
run it with `--network host` and `UWSB_SSH_TARGET=127.0.0.1:22`.

### Single binary

```bash
go install github.com/ubyte-source/ubyte-webssh-bridge/cmd/ubyte-webssh-bridge@2.0.0
ubyte-webssh-bridge -ssh-target 127.0.0.1:22 \
  -server-cert /etc/ssl/bridge.example.test.crt -server-key /etc/ssl/bridge.example.test.key
```

`go install` needs Go 1.27.4; the page is embedded in the binary. Installed on a server, the
bridge reaches the server's own sshd and serves the page on port 8443.

### Behind a proxy that picks the target

```bash
ubyte-webssh-bridge -server-address 127.0.0.1:8080 \
  -server-cert /etc/ssl/bridge.example.test.crt -server-key /etc/ssl/bridge.example.test.key
```

```nginx
location = /ws {
    proxy_pass https://127.0.0.1:8080/ws/192.0.2.10/22;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Without `-ssh-target` the bridge listens on loopback only and reaches the target the path
names. The proxy matches `/ws` exactly, since a prefix `location /ws` would append the rest
of a longer path such as `/ws2` to the port. It writes the target into the upstream path,
passes the upgrade headers and keeps the browser's `Host`, which the bridge compares with
the `Origin`. A proxy on the same host is trusted by the default of
`-server-trusted-proxies`, and a proxy elsewhere is added to it; every trusted proxy
appends its peer to `X-Forwarded-For` or sets `X-Real-IP`, otherwise a client behind it
chooses its own address. The proxy serves the files of `frontend/public` itself, or passes
every other path to the bridge, which serves the same files. Where the integrity of the page
matters, the proxy serves it.

## Using the page

### The card

The page opens on a card titled `SSH-Authentication`: the user name, the password, which may
stay empty, the key zone and `Log In`. Enter submits the card and the dialogs; Escape
cancels a dialog. While it connects the page shows `Connecting…` and `Cancel`.

### The key

Drop a private key on the key zone, click the zone to choose the file, or paste the key text
anywhere on the card. The page reads what `ssh-keygen` writes: OpenSSH keys, plain or
encrypted with bcrypt and `aes128-ctr`, `aes192-ctr` or `aes256-ctr`, and unencrypted PKCS #8,
PKCS #1 and SEC1 keys, of type Ed25519, ECDSA P-256, P-384 or P-521, or RSA of 1024 to 16384
bits, in a file of at most 16384 bytes. The key chip shows the file name, the kind, the
fingerprint as `ssh-keygen -l` prints it and the comment before any passphrase is typed; the
passphrase field appears for an encrypted key only. A key of a kind the browser cannot sign
with is refused as soon as it is read, such as `This browser cannot sign with Ed25519 keys.`
Any other key is refused at once, with the command that converts it where one exists; the
command names the file, quoted for a POSIX shell when it needs it, and `<file>` stands for a
pasted key:

| Key | What to do |
|---|---|
| Encrypted PEM or PKCS #8, or OpenSSH under another cipher | `ssh-keygen -p -f <file>` rewrites it in a form the page reads |
| PuTTY | `puttygen <file> -O private-openssh-new -o <file>.openssh` |
| DSA | `ssh-keygen -t ed25519` makes a new key |
| A hardware key (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) | none: it cannot sign in a browser |

The key stays in the browser. The page reads the file locally and never uploads it,
imports the key as non-extractable WebCrypto keys that live in the tab's memory until the
tab closes or `Forget` drops them, never in storage, and overwrites the passphrase and every
byte of the file once the keys are imported. The bridge receives the public key and, at most
once per connection, the signature of the SSH login request for the user name typed and the
key loaded, before the shell starts. A private key pasted into a field is refused and handed
to the key zone, or dropped while a login runs, so the login keeps its key; pasted into the
terminal, it is sent only after a confirmation. Besides the font size the page stores
nothing: no host key, no user name, no key, no password.

### Keyboard-interactive

Each round of the device shows its name, its instruction and one field per prompt, hidden
unless the device asks for echo; `Continue` answers and `Cancel` ends the session. The
password typed on the card answers the first round that holds one hidden prompt, once per
connection; without a typed password, the password method asks through the same dialog.

### When a session ends

An overlay shows why the session ended, with the exit status or signal, and offers
`Reconnect` (the same user and key; the device asks for the password), `New login` and, with
a key loaded, `Forget key`. The page never reconnects by itself.

### Browsers

A login with a password or keyboard-interactive works in any browser that runs ES2022 modules
and WebSocket. A key needs WebCrypto support for its kind: Ed25519 keys sign in Chrome and Edge
137 or later, Firefox 130 or later, Safari 17 or later and iOS 17 or later; ECDSA and RSA
keys wherever WebCrypto offers ECDSA with the key's curve and RSASSA-PKCS1-v1_5. Inside a
frame the page builds nothing, so no other site can frame it.

Open the page from an `https://` bookmark, never by typing a bare host name.

## Phone and desktop

On a desktop, selecting text copies it, the browser's shortcuts paste (Ctrl+Shift+V, Cmd+V
on macOS), links open in a new tab (`http:` and `https:` only, a device's OSC 8 links
included), and the window title follows the remote. Ctrl (Cmd on macOS) with `+` or `=`
enlarges the font and with `-` shrinks it, between 8 and 32, and with `0` restores the
default; the page remembers the size.

On a phone, a coarse pointer, the terminal fits the visible area above the on-screen
keyboard, and the key bar sits at its bottom:

| Page | Keys |
|---|---|
| 1 | `Esc` `Tab` `Ctrl` `←` `↑` `↓` `→` `⇄` `⌨` |
| 2 | `Alt` `\|` `/` `-` `~` `⇄` `⌨` |
| 3 | `Home` `End` `PgUp` `PgDn` `Ins` `Del` `⇄` `⌨` |
| 4 | `F1` … `F6` `⇄` `⌨` |
| 5 | `F7` … `F12` `⇄` `⌨` |

`⇄` switches page and `⌨` shows or hides the on-screen keyboard. `Ctrl` and `Alt` are
sticky: a tap arms them for the next key, from the bar or the keyboard, and a second tap
within 300 ms locks them until the next tap. The arrows, `PgUp`, `PgDn` and `Del` repeat
while held, after 400 ms, every 60 ms. The keys follow the cursor mode the remote sets.

Gestures on the terminal:

| Gesture | Action |
|---|---|
| Tap | focus the terminal; the keyboard opens |
| Flick right (released within 250 ms, at least 30 px, mostly horizontal) | `Tab` |
| Flick left | `Esc` |
| Flick up / flick down | `↑` / `↓` |
| One-finger drag (still down after 250 ms) | one arrow per character cell travelled, `←`/`→` horizontally and `↑`/`↓` vertically, repeated as the finger travels |
| Two-finger vertical drag | scrolls the scrollback, one line per cell height |
| Pinch | font size 8-32, remembered |
| Long press (500 ms, moved less than 10 px) | a menu at the finger: `Paste` (`navigator.clipboard.readText()` as input), `Copy` (the selection; shown with one) |

A gesture that sends a key vibrates briefly where the browser offers vibration.

## Configuration

The defaults, then the `UWSB_` variables, then the flags given on the command line set the
configuration, each layer over the one below: a flag wins over its variable, a variable over
the default. An empty variable or flag value is unset and leaves the layer below in place.

| Flag | Variable | Type | Default | Range | Meaning |
|---|---|---|---|---|---|
| `-server-address` | `UWSB_SERVER_ADDRESS` | string | `:8443` | `host:port`, host empty or an IP literal, port decimal digits of value 1-65535, leading zeros dropped | TLS listen address of the page and the WebSocket |
| `-server-cert` | `UWSB_SERVER_CERT` | string | `/data/certificate.crt` | a readable PEM file | TLS certificate and its chain |
| `-server-key` | `UWSB_SERVER_KEY` | string | `/data/certificate.key` | a readable PEM file matching the certificate | TLS private key |
| `-server-debug` | `UWSB_SERVER_DEBUG` | bool | `false` | | writes the debug records too |
| `-server-shutdown-timeout` | `UWSB_SERVER_SHUTDOWN_TIMEOUT` | duration | `30s` | 1s-1h | time the sessions have to end after SIGINT or SIGTERM |
| `-server-trusted-proxies` | `UWSB_SERVER_TRUSTED_PROXIES` | list | `127.0.0.0/8,::1/128` | 1-64 entries, each an IP address or a CIDR prefix without a zone, an IPv4-mapped prefix of 96 bits or more | the proxies whose `X-Forwarded-For` and `X-Real-IP` name the client |
| `-conn-max-total` | `UWSB_CONN_MAX_TOTAL` | int | `1000` | 1-100000 | concurrent sessions of the process |
| `-conn-max-per-host` | `UWSB_CONN_MAX_PER_HOST` | int | `10` | 1-100000, at most `-conn-max-total` | concurrent sessions to one target; path route only (with `-ssh-target` set it stops the start) |
| `-rate-burst` | `UWSB_RATE_BURST` | int | `10` | 1-10000 | new sessions one client address opens at once |
| `-rate-interval` | `UWSB_RATE_INTERVAL` | duration | `2s` | 100ms-1h | time a client address takes to regain `-rate-burst` new sessions |
| `-ssh-target` | `UWSB_SSH_TARGET` | string | empty | empty, or `host:port` of an IP address or a DNS name, port decimal digits of value 1-65535, leading zeros dropped | the one target of `/ws`; empty selects `/ws/{host}/{port}` on a loopback listener |
| `-ssh-connect-timeout` | `UWSB_SSH_CONNECT_TIMEOUT` | duration | `10s` | 100ms-5m | TCP connect to the target |
| `-ssh-login-timeout` | `UWSB_SSH_LOGIN_TIMEOUT` | duration | `120s` | 1s-1h | from the TCP connection to the started shell, the login and the user's answers included |
| `-ws-handshake-timeout` | `UWSB_WS_HANDSHAKE_TIMEOUT` | duration | `10s` | 100ms-5m | time a client has to send its request headers and, on the WebSocket, its connect message |
| `-health` | none | bool | | | dial the listen address and exit 0 when it accepts a TCP connection |
| `-version` | none | bool | | | print the version and the Go release and exit |

Integers read in base 10, booleans as Go's `strconv.ParseBool` reads them, durations in Go
syntax (`100ms`, `2s`, `1h`) and a list as entries separated by commas, spaces around an
entry ignored; every range includes both bounds. A value that does not parse or falls
outside its range, a broken rule between settings, a TLS pair that does not load, an unknown
flag, a flag without its value, a malformed flag and an argument that is not a flag each
stop the start with status 2. The bridge reports the problems it finds at once, each naming
its flag and its variable, or, on the command line, the position of the argument; it reads
no flag after that argument and checks no rule between settings unless `-ssh-target` parses.

An unknown `UWSB_` variable never stops the start: a run logs it once at warn when it has a
value, and `-health` does not log it.

Any other variable is ignored.

A setting the selected route does not use stops the start when it is set:
`-conn-max-per-host` with `-ssh-target`, whose one target is capped by `-conn-max-total`.

The client address is the TCP peer, or, when `-server-trusted-proxies` lists the peer, the
address `X-Forwarded-For` names, walked from the right through trusted addresses, or without
that header `X-Real-IP`, as nginx's `set_real_ip_from` with `real_ip_recursive on`; the list
replaces the default, so it keeps `127.0.0.0/8,::1/128` for a proxy on the same host. The
rate bound counts new sessions per client address, its IPv4 address or the /64 of its IPv6
address.

A trusted proxy must append its peer to `X-Forwarded-For` (nginx `$proxy_add_x_forwarded_for`)
or set `X-Real-IP`, otherwise a client behind it chooses its own address.

Any client that reaches the bridge can hold sessions without logging in for
`-ssh-login-timeout` each, up to the caps, and relay password guesses to the target at the
rate bound, so a bridge reachable from untrusted networks belongs behind network access
control.

[.env.example](.env.example) lists every variable with its default, commented out.

## Targets and routes

With `-ssh-target` set, `GET /ws` reaches that target and nothing else, and
`/ws/{host}/{port}` answers 404. With it empty, `GET /ws/{host}/{port}` reaches the target
the path names, and the bridge starts only when `-server-address` listens on a loopback IP
literal, `127.0.0.0/8` or `::1` (`localhost` is refused): a bridge that other hosts reach
never lets a client pick the host, so it is no open relay. A target is an IP literal or a
DNS name and a port of decimal digits whose value is 1 to 65535, written in one way only, so
it holds one slot of `-conn-max-per-host`: a port without its leading zeros (`022` reaches
port `22`), an IP in its canonical form, an IPv4-mapped IPv6 address as its IPv4 address
without its zone, any other IPv6 zone as given (`/ws/fe80::1%25eth0/22` reaches
`[fe80::1%eth0]:22`), and a name in lower case without a trailing dot. A name and a zone are
1 to 253 bytes of labels separated by dots, a label being 1 to 63 ASCII letters, digits, `_`
or `-`, without `-` first or last. On the path route every process that reaches the loopback
address can name any target, so the proxy in front writes the target itself and never
forwards the client's path.

Every other path serves a file of the page, `/` its `index.html`, and answers 404 when no
file matches; a method other than GET and HEAD gets 405.

## TLS

The bridge always serves TLS, 1.2 or higher, with Go's default cipher suites and key
exchanges, from the PEM pair of `-server-cert` and `-server-key`, `/data/certificate.crt`
and `/data/certificate.key` by default. It loads the pair once at the start, so a renewed
certificate takes a restart, and it makes no certificate of its own. It sends no HSTS
header, which would bind every port of the host name.

## SSH compatibility

The client offers x/crypto's secure algorithms, then the insecure ones it still implements:

- key exchange: mlkem768x25519-sha256, curve25519-sha256, ecdh-sha2-nistp256/384/521,
  diffie-hellman-group14-sha256, diffie-hellman-group16-sha512,
  diffie-hellman-group-exchange-sha256, then diffie-hellman-group14-sha1,
  diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha1;
- ciphers: aes128-gcm, aes256-gcm, chacha20-poly1305, aes128/192/256-ctr, then aes128-cbc,
  3des-cbc, arcfour256, arcfour128, arcfour;
- MACs: hmac-sha2-256-etm, hmac-sha2-512-etm, hmac-sha2-256, hmac-sha2-512, hmac-sha1, then
  hmac-sha1-96;
- host keys: the RSA-SHA2, ECDSA and Ed25519 certificates and keys, the ML-DSA certificates
  and keys, then ssh-rsa and its certificate.

The bridge accepts the host key of the first key exchange and pins it for the connection, so
a rekey that presents another key ends the connection. It logs the key's type and SHA256
fingerprint, for a certificate those of the key it certifies, and stores no host key.

x/crypto cannot speak SSH-1, DSA (ssh-dss) host and user keys, aes192-cbc and aes256-cbc,
blowfish and cast128, hmac-md5, umac, the none cipher and compression.

The login methods follow OpenSSH's order: `publickey` with the page's key when one is
loaded, `keyboard-interactive`, then `password`, three tries each for the last two. An RSA
key signs with rsa-sha2-512 or rsa-sha2-256 when the server announces them, and with
`ssh-rsa` when it announces neither. The shell runs on a PTY of terminal type `xterm` with
UTF-8, which old systems know. A DNS name of a target may hold `_` in its labels, as Go's
resolver accepts. The bridge sends no SSH keepalive request, which some old devices answer
by dropping the connection; TCP keep-alive finds a device that vanishes.

## Image

`ubyte/ubyte-webssh-bridge`, built from `Dockerfile` for linux/amd64 at the x86-64 baseline
(`GOAMD64=v1`, so it runs on any 64-bit x86 CPU, however old), holds the binary alone at
`/usr/local/bin/ubyte-webssh-bridge`, on `gcr.io/distroless/static-debian13:nonroot` pinned
by digest, as user 65532, without a shell, with `EXPOSE 8443`. The binary is the entrypoint
and PID 1, so it takes SIGTERM itself and the container's arguments.

The image sets no variable. In the image, settings go through `UWSB_` variables, because the
probe reads only the environment: Docker runs the HEALTHCHECK without the arguments of
`docker run`. The `HEALTHCHECK` runs `ubyte-webssh-bridge -health` every 30 s, within 5 s,
from 10 s after the start, 3 retries. The TLS pair comes from `/data`, mounted read-only.

## Commands

`ubyte-webssh-bridge` runs the bridge. `-h` prints the usage and `-version` prints
`<version> (go=<Go release>)`, the version `dev` unless the build stamps it. `-health` loads
the configuration and dials the listen address over TCP within 4 s, without a TLS handshake:
an empty host and `0.0.0.0` dial `127.0.0.1`, and `::` dials `::1`. The line of `-version`
and the records go to stdout; the usage and the record of a refused configuration go to
stderr.

| Status | Ends |
|--------|------|
| 0 | a stop on SIGINT or SIGTERM; `-h`; `-version`; a probe that connects |
| 1 | a failure at run time: a listen address that cannot be listened on, a server that fails; a probe that does not connect; a usage, a version line or the record of a refused configuration that cannot be written |
| 2 | a configuration or a command line to fix |

The first SIGINT or SIGTERM closes every session with 1001 and stops within
`-server-shutdown-timeout`; past it the bridge closes what remains and logs
`stop outlasted the budget`.

## Logs

The records are JSON lines of Go's `log/slog` on stdout, at info, or at debug with
`-server-debug`, an error under the key `error`:

| Level | Message | Keys |
|-------|---------|------|
| info | `starting ubyte-webssh-bridge` | `version`, `address`, `route`, `target` (pinned route), `certificate`, `certificate_key`, `conn_max_total`, `conn_max_per_host` (path route) |
| warn | `unread variable` | `name`, once per name at the start |
| error | `invalid configuration` | `error`, on stderr |
| error | `listen failed` | `address`, `error` |
| info | `serving` | `address` |
| error | `serve failed` | `error`, when the server fails before the stop |
| debug | `refused` | `reason` (`origin`, `target`, `upgrade`, `rate` or `busy`), `client`, `peer` when it differs, `target` when known, `error` when the upgrade or the close fails |
| debug | `session started` | `session`, `client`, `peer` when it differs, `target` |
| info | `session authenticated` | `session`, `client`, `peer` when it differs, `target`, `user`, `method`, `key_sha256` (publickey), `host_key_type`, `host_key_sha256` |
| debug | `resize failed` | `session`, `error`, when a window size does not reach the device |
| info | `session ended` | `session`, `close_code`, `duration`, `exit_status` when the device sent one |
| debug; warn for 4003 and 4004 | `session failed` | `session`, `client`, `peer` when it differs, `target`, `close_code`, `host_key_type` and `host_key_sha256` once the key exchange completed, `error`, for a session that ends before its login |
| info | `stopping` | `cause` |
| error | `stop outlasted the budget` | `timeout`, `error` |
| error | `health probe failed` | `address`, `error` |
| debug | each line net/http logs | none; the line is the message, such as `http: TLS handshake error from <address>: <error>` |

`session` is a random identifier of 26 characters; `client` is the client address and `peer`
the TCP peer, a trusted proxy; `close_code` is the code the bridge closed with, 1009 when
coder/websocket closed it on a message past 65536 bytes, or 1006 when the page closed it or
went away first; `host_key_type` reads like `ssh-ed25519` or `ssh-rsa`, and the fingerprints
read `SHA256:` and the unpadded base64 of the key's SHA-256, as `ssh-keygen` prints them.
Never logged: the password, the answers, the challenge texts, the `connect` message, the
data signed and the signatures, the terminal bytes either way and the page's storage; the
user name appears only in `session authenticated`, once the device has accepted it.

## Protocol

Binary frames carry terminal bytes both ways; text frames carry one JSON object each, a
control message. The bridge reads messages of at most 65536 bytes, and the page sends its
input in binary frames of at most 8192 bytes, so a paste of any size arrives intact.

| From | Type | Members |
|------|------|---------|
| page | `connect` | `user`, `password` when typed, `key` when loaded, `cols`, `rows` |
| page | `answers` | `answers`, one per prompt of the pending challenge |
| page | `signature` | `id` of the pending sign request, `signature` |
| page | `refusal` | `id` of the pending sign request |
| page | `resize` | `cols`, `rows` |
| bridge | `banner` | `text` |
| bridge | `challenge` | `name`, `instruction`, `prompts` with `text` and `echo` |
| bridge | `sign` | `id`, `data`, `flags` |
| bridge | `ready` | none: the shell is started (the device's first output may come before it) |
| bridge | `exit` | `status` and `signal`, each when the device sent it |

Every member has a bound: a user name of 1 to 256 bytes without control bytes, a password of
1 to 1024 bytes, at most 16 answers of at most 1024 bytes each, a key and a signature of 1 to
4096 characters of canonical standard base64 with padding, `cols` and `rows` from 1 to 999
and `id` from 1 to 4294967295, integers written without a sign, a fraction, an exponent or a
leading zero. A member not listed, a missing one, a value of the wrong JSON kind or outside
its bound, invalid UTF-8, a repeated name or nesting past 2 levels makes the frame invalid,
and the bridge closes with 1008. The bridge cuts the texts it sends at a character: a banner
to 16384 bytes, a challenge's name and instruction to 4096 each, a prompt to 1024 and a
signal name to 32, counted in UTF-8 once each byte of the device that is not UTF-8 is
U+FFFD. It closes with these codes and reasons; the page shows the page text:

| Code | Reason (sent) | When | Page text |
|---|---|---|---|
| 1000 | `session ended` | after `exit` | `Session ended.` plus the exit status or signal |
| 1001 | `server shutting down` | the bridge stops | `The bridge is restarting.` |
| 1008 | `protocol violation` | an invalid or unexpected frame, no connect in time, an invalid key blob | `The page and the bridge disagree; reload the page.` |
| 1009 | `read limited at 65537 bytes` (written by coder/websocket) | a message past 65536 bytes | `A message was too large.` |
| 4002 | `authentication failed` | every method failed | `Authentication failed.` |
| 4003 | `target unreachable` | TCP connect failed or timed out | `The device does not answer.` |
| 4004 | `SSH handshake failed` | version or key exchange failed, no common algorithm | `The device and the bridge share no SSH algorithm, or the device closed the connection.` |
| 4005 | `login timed out` | the login and the opening of the shell outlasted `-ssh-login-timeout` | `The login took too long.` |
| 4006 | `shell refused` | the device refused the PTY or the shell | `The device refused the terminal.` |
| 4007 | `too many sessions` | a cap is full | `Too many sessions; try again later.` |
| 4008 | `too many new sessions, retry later` | the client's rate is spent, or a new client address comes while 65536 are tracked and none has regained `-rate-burst` new sessions | `Too many new sessions; wait a moment.` |
| 4009 | `page stopped answering` | a ping before the `exit` got no pong in 90 s, or a frame to the page other than `exit` waited 90 s | `Connection lost.` |
| 4010 | `connection to the target lost` | the connection to the device failed by a timeout or another error that is neither its close nor a reset, without an exit status or signal; a rekey presented another host key; or the device took no input for 5 minutes | `The connection to the device was lost.` |

A shell that ends without an exit status or signal ends the session with an `exit` without them
and 1000, whether the device then closes or resets the connection.

A connection that ends without a close frame shows `Connection lost.`; the page closes with
1000 when the user ends the session.

## Layout

```text
ubyte-webssh-bridge/
├── cmd/ubyte-webssh-bridge/           # the command: the start, the records, the stop, -health, -version
├── internal/config/                   # the settings: defaults, variables, flags, rules, targets, TLS pair
├── internal/protocol/                 # the messages of the page and of the bridge, the close codes
├── internal/sshclient/                # the SSH leg: dial, algorithms, host key, the page's signer, login, shell
├── internal/session/                  # one page over one WebSocket: states, terminal bytes, keepalive
├── internal/server/                   # HTTPS: routes, headers, files, origin, caps, rate, stop
├── frontend/                          # the page, embedded in the binary
├── frontend/public/                   # index.html and favicon.svg
├── frontend/public/javascript/        # the ES modules of the page, one class each
├── frontend/public/javascript/lib/    # xterm and its fit and web-links add-ons, vendored
├── frontend/public/style/             # the reset, login and terminal style sheets
├── frontend/public/style/lib/         # the style sheet of xterm, vendored
└── frontend/test/                     # the tests of the page, their key generator and message corpus
```

## Dependencies

| Module | Version |
|--------|---------|
| `github.com/coder/websocket` | v1.8.15 |
| `github.com/ubyte-source/go-authware/v2` | v2.3.0 |
| `github.com/ubyte-source/go-jsonfast` | v0.4.1 |
| `go.uber.org/goleak` | v1.3.0 |
| `golang.org/x/crypto` | v0.59.0 |

`goleak` serves the tests alone.

| npm package | Version | Vendored as |
|-------------|---------|-------------|
| `@xterm/xterm` | 6.0.0 | `frontend/public/javascript/lib/xterm.js`, `frontend/public/style/lib/xterm.css` |
| `@xterm/addon-fit` | 0.11.0 | `frontend/public/javascript/lib/addon-fit.js` |
| `@xterm/addon-web-links` | 0.12.0 | `frontend/public/javascript/lib/addon-web-links.js` |

The vendored files are committed, so building and testing the Go code needs neither npm nor
Node; `make vendor-check` proves they equal what `package-lock.json` installs.

## Development

```bash
make ci        # modcheck, vet, lint, vuln, deadcode, test, race, bench-smoke, cover, test-js
make test-js   # the tests of the page, with Node 22 or later
make vendor    # the vendored xterm files, written again after an npm update
make final     # fmtcheck, ci, nilaway, race-repeat, fuzz-final, testtime, vendor-check, treecheck
make help      # every target
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the targets, the tests and the conventions, and
[SECURITY.md](SECURITY.md) for the security policy and the limits.

## Versioning

We use [SemVer](https://semver.org/). Releases are tracked in the repository
[tags](https://github.com/ubyte-source/ubyte-webssh-bridge/tags).

## Authors

- **Paolo Fabris** — [ubyte.it](https://ubyte.it/)

See also the list of [contributors](https://github.com/ubyte-source/ubyte-webssh-bridge/contributors).

## License

MIT, see [LICENSE](LICENSE).

## Support

If ubyte-webssh-bridge is useful for your infrastructure, consider supporting the work:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://coff.ee/ubyte)
