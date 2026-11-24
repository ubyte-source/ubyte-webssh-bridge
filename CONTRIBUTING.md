# Contributing

## Prerequisites

- Go 1.27.4: the `go` line of `go.mod`, which the workflows read; the build stage of `Dockerfile`
  pins the same release by digest.
- Node 22 or later and npm, for the tests of the page and for `make vendor`; building and testing
  the Go code needs neither.
- make, jq for `make testtime`, and Docker for the image.

The Makefile runs every Go tool at a pinned version through `go run`: golangci-lint v2.15.0,
govulncheck v1.9.0, deadcode v0.52.0 and nilaway v0.0.0-20261112030514-ccd005690d1e. Nothing needs a
global install; `GOLANGCI_LINT=<path>`, `GOVULNCHECK=<path>`, `DEADCODE=<path>` and `NILAWAY=<path>`
point the targets at local binaries of the same versions, and `NODE=<path>` and `NPM=<path>` at
another Node. golangci-lint builds and runs with Go 1.27.4 (`GOTOOLCHAIN=go1.27.4`). The tests of
the page run in CI on Node 24.22.3, set up by `actions/setup-node` v7.1.0. `make lint` is the one
way to run the linters, and `make fmt` runs the formatters `make lint` checks. Every target builds
at Go's default amd64 level, the level of the image.

```bash
git clone https://github.com/ubyte-source/ubyte-webssh-bridge.git
cd ubyte-webssh-bridge
make ci
```

## Workflow

1. Branch from `main` under one English word that says what the branch does, such as `keybar`.
2. Change the code together with its tests and with every document the change makes untrue: README
   (the contracts, the configuration, the tables of the page, the image), ARCHITECTURE (the packages
   and the flows), SECURITY (the threat model, the limits and the protections), `.env.example` (the
   variables).
3. Run `make ci` until it passes, and `make fmt` before it when the formatters would change a file.
4. Open a pull request describing what changes, why, and how the change is tested.

`make ci` runs `modcheck`, `vet`, `lint`, `vuln`, `deadcode`, `test`, `race`, `bench-smoke`, `cover`
and `test-js`; `make final` runs the delivery gates on an idle machine. The workflows run on every
push to `main` and every pull request: `lint.yml` runs `lint` and `deadcode`; `test.yml` runs
`modcheck`, `vet`, `test` and `bench-smoke` in one job, `cover` in a second, and `test-js` and
`vendor-check` on Node 24.22.3 in a third; `security.yml` runs `vuln` and CodeQL on Go and
JavaScript, and every month too. `fuzz.yml` runs each fuzz target of `make fuzz-list` for 10 minutes
every month, or for the time a manual run sets. On a release tag, `docker.yml` runs the three
workflows and pushes `ubyte/ubyte-webssh-bridge` only after they pass, with an SBOM and provenance,
and with `latest` for a final release pushed as a tag; a pull request builds the image without
pushing it.

| Target | Gate |
|--------|------|
| `build` | `ubyte-webssh-bridge` for linux/amd64, `CGO_ENABLED=0` and `-trimpath`, stamped with `VERSION` |
| `modcheck` | `go mod download`, `go mod verify`, and a failure when `go.mod` or `go.sum` is not tidy |
| `vet` | `go vet` on linux/amd64 |
| `lint` | golangci-lint v2.15.0 with `.golangci.yml`; gosec runs inside it |
| `fmt` | the formatters of `.golangci.yml` over the module |
| `fmtcheck` | a failure when `gofmt -s` would change a file |
| `vuln` | govulncheck v1.9.0 on the module and the toolchain |
| `deadcode` | deadcode v0.52.0 with and without `-test`; any output fails |
| `nilaway` | nilaway over the module |
| `test` | the tests with `-shuffle=on`, without the race detector |
| `race` | the tests with `-race`, `-shuffle=on` and `CGO_ENABLED=1`, writing `coverage.out` |
| `race-repeat` | the tests with `-race -count=10 -shuffle=on` |
| `cover` | `race`, then `coverage.html`; fails on a statement no test covers |
| `testtime` | a failure on a test slower than `TESTTIME_MAX` seconds (10) in a serial race run |
| `bench` | every benchmark, with `-benchmem` |
| `bench-smoke` | every benchmark 100 times, `-benchtime=100x` |
| `fuzz` | every fuzz target, or the `pkg:Target` entries of `FUZZ_TARGETS`, for `FUZZTIME` each |
| `fuzz-list` | every fuzz target, as the JSON array `fuzz.yml` reads; it fails when there is none |
| `fuzz-final` | every fuzz target for 60 s |
| `test-js` | the tests of the page with `node --test`; fails on a line, branch or function of the modules of `JS_COVERED` no test runs |
| `vendor` | the vendored xterm files, copied from the packages `package-lock.json` installs in a temporary directory |
| `vendor-check` | a failure when a vendored file differs from the one `package-lock.json` installs; it needs the npm registry |
| `treecheck` | after `make clean`, a failure on an artefact, an untracked file of no source kind, a file under `testdata/fuzz`, an empty directory, a file not stored with LF, or a `.gitattributes` without `* text=auto eol=lf` |
| `docker-build` | the image of `Dockerfile` for linux/amd64, stamped with `VERSION`, as `IMAGE:VERSION` and `IMAGE:latest` |
| `final` | `fmtcheck`, `ci`, `nilaway`, `race-repeat`, `fuzz-final`, `testtime`, `vendor-check` and `treecheck`, one after another |
| `clean` | removes the binary, the test binaries, the profiles, the traces, the coverage files and `testtime.json` |

`make help` lists every target.

## Tests

- Go: the tests need no real host. An SSH server of x/crypto runs inside the tests, over `net.Pipe`
  or on a listener of 127.0.0.1:0, with host keys the test generates; both ends of a WebSocket run
  over `net.Pipe`; the HTTPS tests serve on 127.0.0.1:0 with a certificate the test makes. Every
  timer runs in a `testing/synctest` bubble: no `time.Sleep` outside one, and no assertion that
  something did not happen after a wait on the wall clock. Test listeners open with
  `net.ListenConfig.Listen` and the test's context.
- JavaScript: `make test-js` runs `node --test 'frontend/test/*.test.js'` with no npm dependency;
  every module but `main.js` imports under Node. Node's coverage holds `key.js`, `wire.js`, `der.js`,
  `bcrypt.js`, `agent.js`, `websocket.js`, `keybar.js`, `gesture.js` and `storage.js` to every line,
  branch and function; the tests give `keybar.js` and `gesture.js` a document of fake elements.
  `frontend/test/fixtures.js` generates with `node:crypto`, once a run, the keys of every format,
  cipher and kind the page reads and the key texts it refuses: the repository holds no private
  key. `frontend/test/fixtures/protocol.json` is the corpus of messages that the Go and the
  JavaScript tests both judge.
- Every name, address and key comment is invented: `user01`, `user01@example.test`, `example.test`,
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.
- `go.uber.org/goleak` runs from the `TestMain` of `doc_test.go` in `cmd/ubyte-webssh-bridge`,
  `internal/server`, `internal/session` and `internal/sshclient`: a goroutine still alive at the end
  of a package's tests fails the package.
- The fuzz workflow runs every fuzz target monthly, reading the list through `make fuzz-list`. A
  crasher becomes an `f.Add` seed of its target and a unit test that pins it by name, never a file
  under `testdata/fuzz`.
- The tests read the documents: those of `internal/config` hold README's configuration table,
  `.env.example` and the usage of `-h` to the table of settings; those of `cmd/ubyte-webssh-bridge`
  hold SECURITY's limits to the code and to the tests they name, and README's sentence on the
  image's variables to `Dockerfile`; those of the page hold README's key-bar, gesture and close-code
  tables to the modules; a test of `internal/server` holds the policy of `index.html` to the header.
- The output writer and the input forwarder of `internal/session` each have an exact allocation
  count, which `assertAllocs` asserts through `testing.AllocsPerRun`, and a benchmark. A change may
  lower a count, never raise it.

The rules of every Go test:

- Every code file `foo.go` has exactly one sibling `foo_test.go` holding all its tests, benchmarks
  and fuzz targets. `doc.go` has none. `doc_test.go` holds package fixtures only (helpers,
  `TestMain`, shared literals), never tests.
- Test names start with a symbol declared in the sibling file: `Test<Symbol><Scenario>` in
  CamelCase.
- Assertions use the standard library only: `t.Fatalf` and `t.Errorf` with got and want, and
  `errors.Is` on a sentinel for every failure path.
- A concurrency claim has a test that forces its interleaving, through `testing/synctest` or by
  calling a step with a stale load; the race detector runs every test.
- Every fuzz target has a real oracle: the standard library or a reference written independently of
  the code under test.
- A test must fail when the behavior it names breaks; check it by breaking the code once before you
  trust it.

## Code

- Control flow stays linear; one helper per concern, no duplicated logic, no dead code, no code that
  exists only for tests, no mutable package state.
- Errors are wrapped with `%w`; callers that branch get sentinel errors and test them with
  `errors.Is`, never the text.
- Configuration is read, defaulted and validated only in `internal/config`; every other package
  takes the validated values and keeps no default and no clamp of its own.
- Production code logs only through the `*slog.Logger` it receives, with `LogAttrs`, snake_case keys
  and the error under `error`, and never logs a secret.
- Production code reads and writes JSON only through `github.com/ubyte-source/go-jsonfast`, never
  through `encoding/json`, and imports no `unsafe`.
- Struct fields are grouped by meaning, with the boolean flags pooled in one trailing block; govet
  runs every analyzer but `fieldalignment`.
- `//nolint` names one linter and says why the code is safe.
- The page: ES modules of one class each, nested as static members; elements built lazily by
  `getX()` getters with `??=`; state in `#private` fields; events through `data-handle-event` and
  `UHandler.handleEvent`. Nothing hangs on `window`, no file holds an inline script, an inline style
  or an event attribute, text reaches the DOM through `textContent` only, and no module calls
  `console`.

## Comments

- English, present tense, short: at most 3 lines per block, the package comment of `doc.go`
  excepted, and 88 columns.
- They explain what the code cannot say. No history, no notes to self, no citation of an RFC or a
  Markdown file, no restated code, no commented-out code.
- The godoc of every exported identifier is a sentence that starts with its name; one package
  comment per package, in `doc.go`. Every class and public method of the page has JSDoc in the same
  tone.

## Updating xterm

Dependabot opens one pull request for the `@xterm/*` packages, which changes `package.json` and
`package-lock.json`; it fails `vendor-check` until the vendored files follow. Run `make vendor` on
its branch, check the page in a browser, and commit the four files it writes,
`frontend/public/javascript/lib/xterm.js`, `frontend/public/javascript/lib/addon-fit.js`,
`frontend/public/javascript/lib/addon-web-links.js` and `frontend/public/style/lib/xterm.css`, in
the same pull request. A manual update edits the exact versions of `package.json` and runs `npm
install --package-lock-only` before `make vendor`.

## Commit messages

Imperative mood, a subject of at most 50 characters, a blank line, then what changes and why.

## License

Contributions are licensed under the MIT license of the project.
