GO            ?= go
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOLANGCI_LINT ?= GOTOOLCHAIN=go1.27.4 $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
GOVULNCHECK   ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0
DEADCODE      ?= $(GO) run golang.org/x/tools/cmd/deadcode@v0.52.0
NILAWAY       ?= $(GO) run go.uber.org/nilaway/cmd/nilaway@v0.0.0-20261112030514-ccd005690d1e
NODE          ?= node
NPM           ?= npm
IMAGE         ?= ubyte-webssh-bridge
FUZZTIME      ?= 30s
FUZZ_TAGS     ?=
FUZZ_TARGETS  ?=
TESTTIME_MAX  ?= 10
RACECOUNT     ?= 10
FINAL_FUZZTIME ?= 60s
# BUILD_TAGS lists the builds the static gates read, "" being the default build.
BUILD_TAGS     := ""
# JS_COVERED lists the modules of the page, in frontend/public/javascript, whose every line, branch and
# function the tests run.
JS_COVERED     := key wire der bcrypt agent websocket keybar gesture storage
# VENDOR_FILES pairs each file of the npm packages, under node_modules, with the copy
# the page loads.
VENDOR_FILES   := @xterm/xterm/lib/xterm.mjs=frontend/public/javascript/lib/xterm.js \
	@xterm/xterm/css/xterm.css=frontend/public/style/lib/xterm.css \
	@xterm/addon-fit/lib/addon-fit.mjs=frontend/public/javascript/lib/addon-fit.js \
	@xterm/addon-web-links/lib/addon-web-links.mjs=frontend/public/javascript/lib/addon-web-links.js
# VENDOR_INSTALL installs the packages of package-lock.json into a temporary directory,
# $$tmp, which the shell removes when it exits.
VENDOR_INSTALL = tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	cp package.json package-lock.json "$$tmp" && (cd "$$tmp" && $(NPM) ci --ignore-scripts --no-audit --no-fund)
# FUZZ_LIST prints pkg:Target for every fuzz target of the build of FUZZ_TAGS and fails
# when the build has none.
FUZZ_LIST      = mod=$$($(GO) list -m) && out=$$($(GO) test -tags='$(FUZZ_TAGS)' -list='^Fuzz' ./...) && \
	printf '%s\n' "$$out" | awk -v mod="$$mod" '/^Fuzz/ {name[n++] = $$1} /^ok/ { \
		pkg = substr($$2, length(mod) + 2); if (pkg == "") pkg = "."; \
		for (i = 0; i < n; i++) print pkg ":" name[i]; found += n; n = 0 } END { if (found) exit; \
		print "$@: no fuzz target in the build of FUZZ_TAGS=\"$(FUZZ_TAGS)\"" > "/dev/stderr"; exit 1 }'
# SLOW_TESTS selects the passing tests of testtime.json slower than TESTTIME_MAX.
SLOW_TESTS     = select(.Action == "pass" and .Test != null and .Elapsed > $(TESTTIME_MAX)) | \
	"\(.Package) \(.Test) \(.Elapsed)s"

.DEFAULT_GOAL := help

.PHONY: help build ci modcheck vet lint fmt fmtcheck deadcode nilaway vuln test race race-repeat cover testtime \
	bench bench-smoke fuzz fuzz-list fuzz-final test-js vendor vendor-check treecheck docker-build final clean

help: ## List the targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build ubyte-webssh-bridge for linux/amd64 at the x86-64 baseline, stamped with VERSION
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 $(GO) build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o ubyte-webssh-bridge ./cmd/ubyte-webssh-bridge

ci: modcheck vet lint vuln deadcode test race bench-smoke cover test-js ## Run the CI gates

modcheck: ## Download and verify the modules; fail when go.mod or go.sum is not tidy
	$(GO) mod download
	$(GO) mod verify
	$(GO) mod tidy -diff

vet: ## Run go vet on linux/amd64 in each build of BUILD_TAGS
	@for tags in $(BUILD_TAGS); do \
		echo "GOOS=linux GOARCH=amd64 $(GO) vet -tags='$$tags' ./..."; \
		GOOS=linux GOARCH=amd64 $(GO) vet -tags="$$tags" ./... || exit 1; \
	done

lint: ## Run golangci-lint with .golangci.yml in each build of BUILD_TAGS
	@for tags in $(BUILD_TAGS); do \
		echo "$(GOLANGCI_LINT) run $${tags:+--build-tags=$$tags} ./..."; \
		$(GOLANGCI_LINT) run $${tags:+--build-tags=$$tags} ./... || exit 1; \
	done

fmt: ## Format the code with the formatters of .golangci.yml
	$(GOLANGCI_LINT) fmt ./...

fmtcheck: ## Fail when gofmt -s would change a file
	@out=$$("$$($(GO) env GOROOT)/bin/gofmt" -s -l .) && [ -z "$$out" ] || { echo "$$out"; exit 1; }

deadcode: ## Fail on any function deadcode finds unreachable in each build of BUILD_TAGS, with and without tests
	@out=$$(for tags in $(BUILD_TAGS); do $(DEADCODE) -tags="$$tags" ./... && \
		$(DEADCODE) -tags="$$tags" -test ./... || exit 1; done) && [ -z "$$out" ] || { echo "$$out"; exit 1; }

nilaway: ## Fail on any nil flow nilaway finds in the module
	$(NILAWAY) -include-pkgs=$$($(GO) list -m) ./...

vuln: ## Scan the module and the toolchain with govulncheck
	$(GOVULNCHECK) ./...

test: ## Run the tests
	$(GO) test -count=1 -shuffle=on ./...

race: ## Run the tests with the race detector and write coverage.out
	CGO_ENABLED=1 $(GO) test -race -count=1 -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...

race-repeat: ## Run the tests RACECOUNT times with the race detector
	CGO_ENABLED=1 $(GO) test -race -count=$(RACECOUNT) -shuffle=on ./...

cover: race ## Write coverage.html from the race run; fail on any statement no test covers
	$(GO) tool cover -html=coverage.out -o coverage.html
	@awk 'FNR > 1 { n[$$1] = $$2; if ($$3 > 0) hit[$$1] = 1 } END { for (b in n) { all += n[b]; \
		if (b in hit) got += n[b] }; printf "total: %.1f%% of statements\n", all ? 100 * got / all : 100; fflush(); \
		for (b in n) if (n[b] > 0 && !(b in hit)) { print "not covered:", b | "sort"; missed = 1 }; \
		close("sort"); exit missed }' coverage.out

testtime: ## Fail on any test slower than TESTTIME_MAX seconds in a serial race run (outside ci)
	CGO_ENABLED=1 $(GO) test -race -count=1 -p 1 -parallel 1 -json ./... > testtime.json
	@slow=$$(jq -r '$(SLOW_TESTS)' testtime.json) && [ -z "$$slow" ] || { echo "$$slow"; exit 1; }

bench: ## Run every benchmark
	$(GO) test -run='^$$' -bench=. -benchmem ./...

bench-smoke: ## Run every benchmark 100 times
	$(GO) test -run='^$$' -bench=. -benchtime=100x ./...

fuzz: ## Run every fuzz target, or the pkg:Target list FUZZ_TARGETS, for FUZZTIME each in the build of FUZZ_TAGS
	@targets='$(FUZZ_TARGETS)'; [ -n "$$targets" ] || targets=$$($(FUZZ_LIST)) || exit 1; \
	for spec in $$targets; do \
		pkg=$${spec%%:*}; name=$${spec#*:}; \
		$(GO) test -tags='$(FUZZ_TAGS)' -list='^Fuzz' ./$$pkg | grep -qx "$$name" || \
			{ echo "fuzz: ./$$pkg has no fuzz target $$name" >&2; exit 1; }; \
		$(GO) test -tags='$(FUZZ_TAGS)' -run='^$$' -fuzz="^$$name\$$" \
			-fuzztime=$(FUZZTIME) -parallel=4 ./$$pkg || exit 1; \
	done

fuzz-list: ## Print every fuzz target of the build of FUZZ_TAGS as the JSON array the fuzz workflow reads
	@targets=$$($(FUZZ_LIST)) || exit 1; sep=; printf '['; for spec in $$targets; do \
		printf '%s{"pkg":"%s","target":"%s"}' "$$sep" "$${spec%%:*}" "$${spec#*:}"; sep=,; \
	done; printf ']\n'

fuzz-final: ## Run every fuzz target for FINAL_FUZZTIME in the default build
	$(MAKE) fuzz FUZZTIME=$(FINAL_FUZZTIME)

test-js: ## Run the tests of the page with the test runner of Node; fail on a line, branch or function of JS_COVERED no test runs
	$(NODE) --test --experimental-test-coverage $(JS_COVERED:%=--test-coverage-include=frontend/public/javascript/%.js) \
		--test-coverage-lines=100 --test-coverage-branches=100 --test-coverage-functions=100 'frontend/test/*.test.js'

vendor: ## Install package-lock.json in a temporary directory and copy the files of VENDOR_FILES from it
	@$(VENDOR_INSTALL) && for pair in $(VENDOR_FILES); do \
		mkdir -p "$$(dirname "$${pair#*=}")" && cp "$$tmp/node_modules/$${pair%%=*}" "$${pair#*=}" || exit 1; \
	done

vendor-check: ## Fail on a file of VENDOR_FILES that differs from the one package-lock.json installs
	@$(VENDOR_INSTALL) && status=0 && for pair in $(VENDOR_FILES); do \
		cmp "$$tmp/node_modules/$${pair%%=*}" "$${pair#*=}" || status=1; \
	done; exit $$status

treecheck: clean ## Fail on artefacts, stray files, fuzz corpora, empty directories and non-LF files
	@out=$$(git status --porcelain=v1 --ignored --untracked-files=all | sed -n 's/^\(??\|!!\) //p' | \
		awk -v cmds="$$(ls cmd 2>/dev/null)" 'BEGIN { n = split(cmds, c, " "); \
		for (i = 1; i <= n; i++) cmd[c[i]] = 1 }; \
		{ n = split($$0, p, "/"); b = p[n] }; \
		b ~ /\.(out|prof|pprof|test|exe|tmp|bak|orig|rej)$$|~$$|^coverage.*\.html$$/ || (b in cmd) { print; next }; \
		$$0 == ".env" || $$0 ~ /^\.(idea|vscode)\// || $$0 ~ /(^|\/)testdata\// { next }; \
		b ~ /\.(go|md|yml|yaml|json|html|js|css|svg)$$/ { next }; \
		b ~ /^(go\.mod|go\.sum|LICENSE|Makefile|Dockerfile|\.gitignore|\.gitattributes|\.dockerignore|\.env\.example)$$/ { next }; \
		{ print }') && \
		[ -z "$$out" ] || { echo "treecheck: artefacts or untracked files of no source kind:"; echo "$$out"; exit 1; }
	@out=$$(find . -path ./.git -prune -o -type d -empty -print) && [ -z "$$out" ] || \
		{ echo "treecheck: empty directories:"; echo "$$out"; exit 1; }
	@out=$$(git ls-files --eol --cached --others --exclude-standard | awk '$$2 != "w/" && \
		($$1 !~ /^i\/(lf|-text|none)?$$/ || $$2 !~ /^w\/(lf|-text|none)$$/)') && [ -z "$$out" ] || \
		{ echo "treecheck: files not stored with LF (git add --renormalize . fixes the index):"; echo "$$out"; exit 1; }
	@grep -qx '\* text=auto eol=lf' .gitattributes || \
		{ echo "treecheck: .gitattributes lacks * text=auto eol=lf"; exit 1; }
	@out=$$(find . -path ./.git -prune -o -path '*/testdata/fuzz/*' -type f -print) && [ -z "$$out" ] || \
		{ echo "treecheck: files of the fuzzing engine under testdata/fuzz (a crasher is an f.Add seed):"; \
		echo "$$out"; exit 1; }

docker-build: ## Build the image of Dockerfile for linux/amd64, stamped with VERSION, as IMAGE:VERSION and IMAGE:latest
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

final: ## Run the delivery gates one after another on an idle machine
	@for gate in fmtcheck ci nilaway race-repeat fuzz-final testtime vendor-check treecheck; do \
		$(MAKE) $$gate || exit 1; \
	done

clean: ## Remove the binary, test binaries, profiles, traces, coverage reports and testtime.json
	rm -f ubyte-webssh-bridge *.test *.prof *.pprof *.trace coverage*.out coverage.html testtime.json
