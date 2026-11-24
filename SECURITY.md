# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x | yes |
| 1.4.x and earlier | no |

Fixes go to the latest 2.0.x release.

## Reporting a vulnerability

Do not open a public issue. Report it privately through GitHub's private vulnerability reporting:
[open an advisory](https://github.com/ubyte-source/ubyte-webssh-bridge/security/advisories/new) from
the Security tab of the repository, with a description, the steps to reproduce and the impact.

## Scope

The binary, the page it embeds and serves from `frontend/public`, and the image `Dockerfile` builds.
In scope:

- a private key or its passphrase that leaves the browser, or reaches the page's storage;
- a password, an answer or terminal data in a log record, an error, the page's storage or the hands
  of anyone but the device;
- a signature the page gives outside its signing policy;
- a session that reaches a target other than the pinned one, or a target that a client names through
  a listener beyond loopback;
- a crash, a hang, or memory, goroutines, sessions or log records without a bound, that bytes of a
  client or of a device trigger;
- the client address taken from the headers of a peer that `-server-trusted-proxies` does not list;
- the page running inside a frame, loading anything that is not its own, writing text of the device,
  the bridge or a file other than as text, or opening a link of a scheme other than `http:` and
  `https:`.

The reverse proxy in front of the bridge, the devices behind it and the network between them are
outside it.

## Threat model

### Assets

- **The private key and its passphrase**, which stay in the browser.
- **Passwords and keyboard-interactive answers**, which cross the bridge on their way to the device.
- **The devices behind the bridge**, which a session controls.
- **Terminal data**, both ways.

No message of the protocol carries private material. The bridge reads every message of the page
against this table and refuses a member it does not list, so a `connect` with a `private` or a
`passphrase` member closes the session with 1008:

| Message | From | Carries |
|---------|------|---------|
| `connect` | page | the user name, the password when one is typed, the public-key blob when a key is loaded, the terminal size |
| `answers` | page | one answer per prompt of the pending challenge |
| `signature` | page | one SSH signature for the pending sign request |
| `refusal` | page | the `id` of the pending sign request |
| `resize` | page | the terminal size |
| `banner`, `challenge` | bridge | texts of the device |
| `sign` | bridge | the bytes of the SSH login request to sign, and the agent flags |
| `ready`, `exit` | bridge | the start of the shell, its exit status or signal |

The bridge has no code that reads a private key, and the passphrase is typed into the page and used
there.

### Trust boundaries

- **Browser and bridge**: TLS 1.2 or higher with the configured pair; the WebSocket is accepted only
  with an `Origin` whose host equals `Host`; the page and every response carry one
  Content-Security-Policy.
- **Bridge and device**: SSH. The bridge accepts the device's host key and logs its fingerprint; the
  device leg is as trustworthy as the network between bridge and device. The key of the first
  exchange is pinned for the connection, so a rekey that presents another key ends it with 4010.
- **Client and proxy**: the bridge reads `X-Forwarded-For` and `X-Real-IP` only from a TCP peer that
  `-server-trusted-proxies` lists, `127.0.0.0/8,::1/128` by default. It walks `X-Forwarded-For` from
  the right through trusted addresses, and the first address that is not trusted is the client, as
  nginx's `set_real_ip_from` with `real_ip_recursive on`; an entry that is not an IP address stops
  the walk at the last address read, and when every entry is trusted the client is the leftmost.
  Without `X-Forwarded-For`, an `X-Real-IP` that parses as an IP address is the client. `Forwarded`
  is not read, and the headers of any other peer are not read at all. A trusted proxy must append
  its peer to `X-Forwarded-For` (nginx `$proxy_add_x_forwarded_for`) or set `X-Real-IP`.

### Attackers and what stops them

- **A foreign web page** cannot open a session: the bridge requires an `Origin` and refuses one
  whose host differs from `Host`. It cannot frame the page under an overlay: the header
  `frame-ancestors 'none'` keeps the page out of frames where the bridge serves it, and the page
  builds nothing inside a frame wherever it is served.
- **A network attacker on the browser leg** meets TLS. The WebSocket compresses nothing, so no
  secret is compressed beside data of the page. The bridge sends no HSTS header, so users open the
  page from an `https://` bookmark, never by typing a bare host name.
- **Anyone who reaches the bridge** finds no open relay: one pinned target, or the path route on a
  loopback listener only. Every message of the page is bounded and read as strict JSON; the caps
  bound the concurrent sessions and the rate bounds the new sessions of each client address, read
  from headers only when the TCP peer is a trusted proxy.
- **A compromised bridge** obtains everything typed into the page while it runs, the passwords, the
  answers and the terminal input and output, and can type into every live session it carries, so it
  controls the devices of those sessions. The signing policy bounds what it gains on other servers:
  at most one signature per Connect, over a login request for the typed user with a session
  identifier it chooses, so it could log in once, as that user, to another server that trusts the
  key, for as long as the tab is open. It never obtains the private key, the passphrase, or a
  signature after the tab closes.
- **A compromised file server**, the bridge when it serves the page or the web server that does, can
  change the page itself, as for every web application. Where the integrity of the page matters, the
  reverse proxy that picks the target serves the page itself; the meta Content-Security-Policy keeps
  the page from loading anything that is not its own.

### What does not stop an attacker

- A party between the bridge and the device can pose as the device and read the passwords and
  answers typed for it.
- A signature the page gives cannot be replayed to another server, since it covers the session
  identifier of that one connection.
- A trusted proxy that does not append its peer to `X-Forwarded-For` or set `X-Real-IP` lets a
  client behind it choose its own address, so the rate bound counts what that client says.
- Any client that reaches the bridge can hold sessions without logging in for `-ssh-login-timeout`
  each, up to the caps, and relay password guesses to the target at the rate bound, so a bridge
  reachable from untrusted networks belongs behind network access control.
- On the path route every process that reaches the loopback address can name any target, so the
  proxy in front writes the target itself and never forwards the client's path.
- The bridge cannot erase every copy of a password or an answer: Go strings, x/crypto's packet
  buffers, crypto/tls's decrypted input and the buffered reader of the WebSocket's connection keep
  them until their memory is reused, readable by whoever reads the memory of the process.

## Known limits

| Limit | Value | Where | Past it | Pinned by |
|-------|-------|-------|---------|-----------|
| Concurrent sessions of the process | `1000` (`UWSB_CONN_MAX_TOTAL`) | internal/server caps.go | closed with 4007 | `TestCapsAdmitStopsAtMaxTotal`, `TestCapsAdmitCountsAPinnedTargetAgainstMaxTotal`, `TestServeSocketClosesBusy` |
| Concurrent sessions to one target (path route) | `10` (`UWSB_CONN_MAX_PER_HOST`) | internal/server caps.go | closed with 4007 | `TestCapsAdmitStopsAtMaxPerHost`, `TestCapsReleaseRetiresTheLastSlot`, `TestValidatePerHostOverTotal` |
| New sessions of one client address | `10` at once, then one per 200 ms (`UWSB_RATE_BURST`, `UWSB_RATE_INTERVAL`) | internal/server rate.go | closed with 4008 | `TestLimiterAdmitGrantsTheBurstThenOnePerEmission`, `TestRateKeyGroupsAnIPv6Slash64`, `TestServeSocketKeysTheRateByTheForwardedClient` |
| Client addresses the rate bound tracks | `65536` | internal/server rate.go | a new address is closed with 4008 | `TestLimiterAdmitRefusesANewKeyPastTheBound`, `TestLimiterAdmitSweepsTheFullCells` |
| Trusted proxy entries | `64` in the list of `-server-trusted-proxies` | internal/config | the start stops (exit 2) | `TestParsePrefixesBoundsTheEntries`, `TestParsePrefixesRefusesEachBadEntry` |
| Request line and headers (HTTP/1.1) | `20480` bytes (16384 plus net/http's 4096 of read slack) | internal/server server.go | 431 | `TestServeBoundsTheRequestHeaders` |
| Request headers and the connect message | `10s` (`UWSB_WS_HANDSHAKE_TIMEOUT`) | internal/server, internal/session | connection closed; 1008 | `TestServerHTTPServerBoundsEachConnection`, `TestRunNoConnect` |
| A file response | `60s` | internal/server server.go | connection closed | `TestServerHTTPServerBoundsEachConnection` |
| An idle HTTP connection | `120s` | internal/server server.go | connection closed | `TestServerHTTPServerBoundsEachConnection` |
| One message from the page | `65536` bytes | internal/protocol, internal/session | closed with 1009 | `TestMaxMessageBytes`, `TestRunMessageBounds` |
| JSON nesting of a page message | `2` | internal/protocol | closed with 1008 | `TestDecodeRefusesNestingPastTwo` |
| User name, password, one answer | `256`, `1024`, `1024` bytes | internal/protocol | closed with 1008 | `TestDecodeBoundsUserPasswordAnswer` |
| Public key, signature (base64) | `4096` characters | internal/protocol | closed with 1008 | `TestDecodeBoundsBase64` |
| Answers of one message | `16` | internal/protocol | closed with 1008 | `TestDecodeBoundsAnswerCount` |
| Terminal columns and rows | `1`-`999` | internal/protocol | closed with 1008 | `TestDecodeBoundsSize` |
| TCP connect to the target | `10s` (`UWSB_SSH_CONNECT_TIMEOUT`) | internal/sshclient | closed with 4003 | `TestDialUnreachable`, `TestRunFailures` |
| The login and the opening of the shell, the user's answers included | `120s` (`UWSB_SSH_LOGIN_TIMEOUT`) | internal/sshclient | closed with 4005 | `TestLogInTimeout`, `TestClientOpenTimesOut`, `TestRunOpeningTimesOut` |
| Tries of keyboard-interactive and of password | `3` each | internal/sshclient | the method fails | `TestPrompterPasswordThreeTries` |
| Keyboard-interactive rounds of one login | `32` | internal/sshclient | 4002 | `TestPrompterChallengeRounds` |
| Prompts of a round | `16` | internal/sshclient | 4002 | `TestPrompterChallengeBounds` |
| Bytes of a banner shown | `16384` | internal/protocol | the rest is dropped | `TestEncodeBannerCutsText`, `TestPrompterBanner` |
| Bytes of a prompt; of a name or instruction shown | `1024`; `4096` | internal/protocol | the rest is dropped | `TestEncodeChallengeCutsTexts`, `TestPrompterChallengeLongTexts` |
| Pong after a ping | `90s`, a ping every `30s` | internal/session | closed with 4009; behind the `exit`, closed with 1000 | `TestSessionPingWithoutPong`, `TestSessionPingSkippedWhileBlocked`, `TestSessionFinishSilentPage` |
| A frame the page does not take | `90s` | internal/session | closed with 4009 | `TestOutputWriteTimeout` |
| A write to the shell the device does not take | `5m` | internal/session | closed with 4010 | `TestSessionForwardInputTimeout`, `TestShellWriteEndedByContext` |
| Bytes of an exit signal name sent | `32` | internal/protocol | cut | `TestEncodeExitCutsSignal` |
| The stop | `30s` (`UWSB_SERVER_SHUTDOWN_TIMEOUT`) | internal/server | sessions closed at once | `TestServeStopOutlastsTheBudget`, `TestServeStopsTheSessions` |
| Key file the page reads | `16384` bytes | frontend key.js | refused at once | `key: refuses a file over 16384 bytes before reading it` |
| bcrypt-pbkdf rounds | `2048` | frontend key.js | refused | `key: refuses bcrypt rounds over 2048 and reads 2048` |
| RSA modulus of a key the page loads | `1024`-`16384` bits | frontend key.js, internal/sshclient | refused | `key: refuses an RSA modulus outside 1024-16384 bits` |
| Signatures the page gives per connection | `1` | frontend agent.js | refusal | `agent: refuses a second signature on one WebSocket and signs again on the next` |
| Input frame the page sends | `8192` bytes | frontend websocket.js | cut in several frames | `websocket: sendInput cuts 20000 bytes into frames of 8192, 8192 and 3616 bytes, in order` |

The bytes of a text the bridge sends count its UTF-8 once each byte of the device that is not
UTF-8 is U+FFFD, as the page counts them, and a text past its bound is cut at a character. A
session has no bound on its length: a live page that idles is the user's choice, and the keepalive
finds a page that vanished within two minutes. The bridge holds no terminal output of its own: the
output writer sends each chunk of at most 32768 bytes as it comes, and a frame the page does not
take within 90 s ends the session.

## Built-in protections

- **The page as the agent**: the page reads the private key locally, imports it as non-extractable
  WebCrypto keys that live in the tab's memory until the tab closes or `Forget` drops them, and
  overwrites the passphrase and every byte of the file once the keys are imported. The bridge
  receives the public key and signatures, nothing more.
- **The signing policy**: the page signs only an SSH `publickey` login request for the user typed
  and the key loaded, once per WebSocket the user opened with Connect or Reconnect, before `ready`,
  whose algorithm agrees with the flags and the key; it refuses everything else.
- **Signatures checked**: the bridge relays a signature only when it verifies under the announced
  key for the bytes and the algorithm of the request.
- **The host key pinned within a connection**: a rekey that presents another key than the first
  exchange's ends the connection.
- **No open relay**: with `-ssh-target` empty, the start stops unless the listen address is a
  loopback IP literal.
- **The client address only from trusted proxies**: the headers of any other peer are not read, and
  `-server-trusted-proxies` holds at most 64 entries.
- **Secrets masked and dropped**: the password and the answers travel as `secret.Value`, written as
  `***` by fmt, slog and JSON; the bridge overwrites the bytes of each text frame once decoded,
  zeroes the one pointer through which the login methods reach the typed password as soon as the
  handshake returns, and drops the `connect` message and the answers when the login ends. No record
  holds a password, an answer, a challenge text, signed data, a signature or terminal bytes; the
  user name appears only once the device accepted it.
- **Strict JSON**: a page message is one object of valid UTF-8, nested at most 2 levels, without a
  repeated name, a member not listed or a value of the wrong JSON kind or outside its bound; an
  error names the member and never the value.
- **Headers**: every response carries the Content-Security-Policy, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin` and `Cache-Control: no-cache`.
- **CSP and the frame check**: `default-src 'none'`, scripts and styles from the page's origin only
  (styles inline too, which xterm writes at run time), `connect-src 'self'`, `frame-ancestors
  'none'` in the header; the page builds nothing inside a frame, holds no inline script, writes text
  of the device, the bridge and a file through `textContent` only, opens links of `http:` and
  `https:` only, and stores the font size alone.
- **The image**: `gcr.io/distroless/static-debian13:nonroot` pinned by digest, the binary alone,
  user 65532, no shell.

## Continuous verification

The Makefile runs each tool at its pinned version through `go run`:

- `make lint`: golangci-lint v2.15.0, built with Go 1.27.4, with gosec among its linters;
- `make vuln`: govulncheck v1.9.0, on the module and the toolchain;
- `make deadcode`: deadcode v0.52.0, with and without the tests;
- `make nilaway`: nilaway v0.0.0-20261112030514-ccd005690d1e, over the module.

CodeQL analyses the Go code and the JavaScript of the page, the vendored xterm files excepted, on
every push to `main`, every pull request and every month. `make ci` runs lint, vuln and deadcode
with the tests: the race detector on every test, a coverage gate of 100% of statements, and the
tests of the page. `make fuzz` runs the fuzz targets of the decoder of the page's messages, of the
encoder of a challenge, of the target grammar, of the page's signer and of the client address, each
against an oracle written apart from the code under test, and the fuzz workflow runs them every
month.
