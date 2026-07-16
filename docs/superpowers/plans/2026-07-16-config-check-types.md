# Config File with Per-Host Check Types Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `-c/--config PATH` flag loading a YAML map of per-host settings (currently just `type: iproute2|aws`), so AWS EC2 hosts — whose public IP is NAT'd in AWS infrastructure and invisible to `ip address` — are checked via IMDS as well; `--concurrency`'s short flag moves to `-C`.

**Architecture:** A new `config.go` holds the `checkCommands` type→remote-command map (single source of truth for known types), the multi-line `awsCommand` IMDS shell snippet, `HostConfig`, and `loadConfig` (strict YAML via `KnownFields(true)`). `Check` gains a `Type` field resolved by `parseInput` from the config, looked up by the **unstripped** hostname before `-s`/`-S` mutate it. A new `sshArgs` helper builds the ssh argv from the check's type; `runCheck` uses it.

**Tech Stack:** Go 1.25, kong (flags), `gopkg.in/yaml.v3` (new dependency — the only one added).

**Spec:** `docs/superpowers/specs/2026-07-16-config-check-types-design.md`

## Global Constraints

- Logging via `slog` only — never stdlib `log`. Fatal startup errors are `log.Error(...)` then `os.Exit(1)`.
- Config file is YAML, keyed by **unstripped** hostname; only second-level key is `type`, values `iproute2` (default) or `aws`. Unknown keys/types are startup errors.
- No `-c` flag → nil config map → all hosts `iproute2`. Empty `type` in an entry also defaults to `iproute2`. Config hosts absent from stdin are silently ignored.
- Commit messages use Conventional Commits with trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run all tests with `go test ./...` from the repo root `/home/gavin/work/ipsentinel`.

---

### Task 1: Config loading (`config.go`)

**Files:**
- Create: `config.go`
- Create: `config_test.go`
- Modify: `go.mod`/`go.sum` (via `go get`)

**Interfaces:**
- Produces: `checkCommands map[string]string` (keys `"iproute2"`, `"aws"`); `const defaultCheckType = "iproute2"`; `type HostConfig struct { Type string }`; `func loadConfig(path string) (map[string]HostConfig, error)`.

- [ ] **Step 1: Write the failing tests**

Create `config_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes content to a temp config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `# ipsentinel config
web1.example.com:
  type: aws
web2.example.com:
  type: iproute2
web3.example.com:
`)
	config, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	want := map[string]HostConfig{
		"web1.example.com": {Type: "aws"},
		"web2.example.com": {Type: "iproute2"},
		"web3.example.com": {}, // null entry: empty type, defaults later
	}
	if len(config) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(config), len(want), config)
	}
	for host, hc := range want {
		if config[host] != hc {
			t.Errorf("config[%q] = %+v, want %+v", host, config[host], hc)
		}
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	config, err := loadConfig(writeConfig(t, ""))
	if err != nil {
		t.Fatalf("empty config file should not error: %v", err)
	}
	if len(config) != 0 {
		t.Errorf("got %d entries, want 0", len(config))
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		errWant string // substring expected in the error
	}{
		{"malformed yaml", "web1: [unclosed\n", "parsing"},
		{"unknown type", "web1.example.com:\n  type: gcp\n", `unknown type "gcp"`},
		{"unknown key", "web1.example.com:\n  tyep: aws\n", "tyep"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errWant) {
				t.Errorf("error %q does not contain %q", err, tt.errWant)
			}
		})
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nonexistent.yml")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestCheckCommands(t *testing.T) {
	if cmd := checkCommands["iproute2"]; cmd != "ip address" {
		t.Errorf(`checkCommands["iproute2"] = %q, want "ip address"`, cmd)
	}
	aws := checkCommands["aws"]
	for _, needle := range []string{"ip address", "169.254.169.254", "public-ipv4", "X-aws-ec2-metadata-token"} {
		if !strings.Contains(aws, needle) {
			t.Errorf(`checkCommands["aws"] missing %q`, needle)
		}
	}
	if _, ok := checkCommands[defaultCheckType]; !ok {
		t.Errorf("defaultCheckType %q is not a checkCommands key", defaultCheckType)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... 2>&1 | head -20`
Expected: compile FAIL — `undefined: loadConfig`, `undefined: HostConfig`, `undefined: checkCommands`, `undefined: defaultCheckType`.

- [ ] **Step 3: Add the yaml dependency**

Run: `go get gopkg.in/yaml.v3@latest`
Expected: go.mod gains `gopkg.in/yaml.v3`.

- [ ] **Step 4: Write the implementation**

Create `config.go`:

```go
// Per-host configuration for ipsentinel: the -c/--config YAML file maps
// (unstripped) hostnames to settings — currently just the check type.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultCheckType is used for hosts with no config entry or an empty type.
const defaultCheckType = "iproute2"

// awsCommand runs `ip address` and appends the instance's public IPv4 from
// the EC2 Instance Metadata Service (IMDSv2 with IMDSv1 fallback: no token =>
// header omitted). EC2 public IPs are 1:1 NAT mappings held in AWS
// infrastructure, not configured on the instance, so they never appear in
// `ip address` output. curl failures are tolerated (|| true) so an IMDS
// hiccup or missing curl degrades to plain `ip address` matching rather than
// an ssh error; -m 2 caps each curl well inside the overall ssh timeout.
const awsCommand = `ip address
TOKEN=$(curl -sf -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null) || true
curl -sf -m 2 ${TOKEN:+-H "X-aws-ec2-metadata-token: $TOKEN"} http://169.254.169.254/latest/meta-data/public-ipv4 || true`

// checkCommands maps a check type to the remote command ssh runs on the
// target host. It is the single source of truth for known types: config
// validation checks `type` values against these keys.
var checkCommands = map[string]string{
	"iproute2": "ip address",
	"aws":      awsCommand,
}

// HostConfig holds the per-host settings from the -c/--config file.
type HostConfig struct {
	Type string `yaml:"type"`
}

// loadConfig reads the YAML config file at path: a map keyed by (unstripped)
// hostname with per-host settings. Unknown second-level keys and unknown
// type values are errors, so typos fail loudly at startup rather than
// silently checking the wrong thing.
func loadConfig(path string) (map[string]HostConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	config := make(map[string]HostConfig)
	if err := dec.Decode(&config); err != nil {
		if errors.Is(err, io.EOF) {
			return config, nil // empty config file
		}
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for host, hc := range config {
		if hc.Type == "" {
			continue // defaults to defaultCheckType at lookup time
		}
		if _, ok := checkCommands[hc.Type]; !ok {
			return nil, fmt.Errorf("%s: host %s: unknown type %q (known: %s)",
				path, host, hc.Type, strings.Join(slices.Sorted(maps.Keys(checkCommands)), ", "))
		}
	}
	return config, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./...`
Expected: PASS (all tests, including pre-existing ones).

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go go.mod go.sum
git commit -m "feat: add YAML per-host config loading with check-type validation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `Check.Type` resolution in `parseInput`

**Files:**
- Modify: `main.go` (Check struct ~line 40; parseInput ~lines 158-210; run ~lines 116-119; main ~line 111)
- Modify: `main_test.go` (all parseInput call sites and Check literals)

**Interfaces:**
- Consumes: `HostConfig`, `defaultCheckType` from Task 1.
- Produces: `Check{Hostname, IP, Type string}`; `parseInput(r io.Reader, alerter Alerter, stripAll bool, domain string, config map[string]HostConfig) ([]Check, int)`; `run(cli CLI, config map[string]HostConfig, log *slog.Logger, r io.Reader) int` (main passes `nil` for now; Task 4 wires the real config).

- [ ] **Step 1: Write the failing test**

Add to `main_test.go`:

```go
func TestParseInputConfigTypes(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar.example.com,10.0.0.2\n"
	config := map[string]HostConfig{
		"foo.example.com": {Type: "aws"}, // keyed by unstripped hostname
	}

	// The config lookup uses the hostname as read from stdin, even when
	// stripping rewrites what is stored on the Check.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, true, "", config)
	want := []Check{{"foo", "10.0.0.1", "aws"}, {"bar", "10.0.0.2", "iproute2"}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i, w := range want {
		if checks[i] != w {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], w)
		}
	}

	// A nil config defaults every check to iproute2.
	var alerter2 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter2, false, "", nil)
	for i, c := range checks {
		if c.Type != "iproute2" {
			t.Errorf("nil-config check[%d].Type = %q, want %q", i, c.Type, "iproute2")
		}
	}

	// An entry with an empty Type also defaults to iproute2.
	var alerter3 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter3, false, "",
		map[string]HostConfig{"foo.example.com": {}})
	if checks[0].Type != "iproute2" {
		t.Errorf("empty-type check Type = %q, want %q", checks[0].Type, "iproute2")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... 2>&1 | head -10`
Expected: compile FAIL — parseInput takes 4 arguments, and `Check` composite literals have too many values.

- [ ] **Step 3: Implement**

In `main.go`, add the `Type` field to `Check`:

```go
// Check is a single hostname,ip pair to verify.
type Check struct {
	Hostname string
	IP       string
	Type     string // check type: a checkCommands key, resolved by parseInput
}
```

Change the `parseInput` signature and doc comment (add the final sentence and the `config` parameter):

```go
// parseInput reads hostname,ip pairs from r, one per line. Blank lines and
// lines beginning with '#' are ignored. Malformed lines, invalid hostnames, and
// unparseable ips are alerted and counted; it returns the valid checks plus the
// failure count. Each ip is parsed and stored in its canonical text form. When
// domain is non-empty, that suffix is stripped from each validated hostname
// (see stripDomain); when stripAll is set, the hostname is then reduced to its
// leftmost DNS label (see stripHostname). Each check's Type is resolved from
// config — keyed by the unstripped hostname — before any stripping, defaulting
// to defaultCheckType for absent hosts or empty types.
func parseInput(r io.Reader, alerter Alerter, stripAll bool, domain string, config map[string]HostConfig) ([]Check, int) {
```

In the parse loop, resolve the type before stripping and store it on the Check (replacing the current `ip = addr.String()` ... `checks = append` block):

```go
		// Store the canonical text form so matching against `ip address`
		// output is spelling-insensitive (e.g. FE80::1 => fe80::1).
		ip = addr.String()
		// Resolve the check type before stripping: config is keyed by the
		// hostname as it appears on stdin.
		ctype := defaultCheckType
		if hc, ok := config[host]; ok && hc.Type != "" {
			ctype = hc.Type
		}
		if domain != "" {
			host = stripDomain(host, domain)
		}
		if stripAll {
			host = stripHostname(host)
		}
		checks = append(checks, Check{Hostname: host, IP: ip, Type: ctype})
```

Thread config through `run` (main's call updated to pass `nil` for now — Task 4 wires the real config):

```go
func run(cli CLI, config map[string]HostConfig, log *slog.Logger, r io.Reader) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.StripAll, cli.Strip, config)
```

and in `main`:

```go
	os.Exit(run(cli, nil, log, os.Stdin))
```

- [ ] **Step 4: Update existing tests for the new signature and field**

In `main_test.go`, every `parseInput(...)` call gains a final argument: `nil` (lines ~38, 67, 101, 117, 146, 172). Every positional `Check` literal gains `"iproute2"` as its third element:

`TestParseInput`:

```go
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "", nil)

	wantChecks := []Check{
		{"host1", "10.0.0.1", "iproute2"},
		{"host2", "10.0.0.2", "iproute2"},
		{"sub.host_alias-1.example.com", "10.0.0.7", "iproute2"},
	}
```

`TestParseInputRejectsFlagSmuggling`:

```go
	checks, failures := parseInput(strings.NewReader("-oProxyCommand=evil,10.0.0.1\n"), &alerter, false, "", nil)
```

`TestParseInputStrip`:

```go
	checks, failures := parseInput(strings.NewReader(input), &alerter, true, "", nil)
	wantStripped := []Check{{"foo", "10.0.0.1", "iproute2"}, {"bar", "10.0.0.2", "iproute2"}}
```

and:

```go
	checks, _ = parseInput(strings.NewReader(input), &alerter2, false, "", nil)
```

`TestParseInputStripDomain`:

```go
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "example.com", nil)
	want := []Check{{"foo", "10.0.0.1", "iproute2"}, {"bar.other.com", "10.0.0.2", "iproute2"}, {"baz", "10.0.0.3", "iproute2"}}
```

`TestParseInputValidatesIP`:

```go
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "", nil)

	want := []Check{
		{"host1", "10.0.0.1", "iproute2"},
		{"host5", "fe80::1", "iproute2"},
		{"host6", "fe80::1", "iproute2"},
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: resolve per-host check type in parseInput from config

The config lookup is keyed by the unstripped hostname (as read from
stdin), before -s/-S rewrite it, per the spec.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `sshArgs` dispatch in `runCheck`

**Files:**
- Modify: `main.go` (runCheck ~lines 216-243)
- Modify: `main_test.go` (new test)

**Interfaces:**
- Consumes: `Check.Type` (Task 2), `checkCommands`/`defaultCheckType` (Task 1).
- Produces: `sshArgs(c Check, connectTimeoutSeconds int) []string`.

- [ ] **Step 1: Write the failing test**

Add to `main_test.go` (add `"slices"` to the imports):

```go
func TestSSHArgs(t *testing.T) {
	c := Check{Hostname: "web1", IP: "10.0.0.1", Type: "iproute2"}
	want := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", "web1", "ip address"}
	if got := sshArgs(c, 10); !slices.Equal(got, want) {
		t.Errorf("sshArgs(iproute2) = %q, want %q", got, want)
	}

	// aws type: same argv shape, remote command is the IMDS snippet.
	c.Type = "aws"
	got := sshArgs(c, 10)
	if len(got) != len(want) {
		t.Fatalf("sshArgs(aws) has %d args, want %d: %q", len(got), len(want), got)
	}
	remote := got[len(got)-1]
	if !strings.Contains(remote, "ip address") || !strings.Contains(remote, "169.254.169.254") {
		t.Errorf("aws remote command missing expected content: %q", remote)
	}

	// Unknown or empty type falls back to the default command, so a
	// zero-value Check still runs a sane check.
	c.Type = ""
	got = sshArgs(c, 10)
	if got[len(got)-1] != "ip address" {
		t.Errorf("empty type remote command = %q, want %q", got[len(got)-1], "ip address")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... 2>&1 | head -10`
Expected: compile FAIL — `undefined: sshArgs`.

- [ ] **Step 3: Implement**

In `main.go`, add `sshArgs` above `runCheck` and use it (also update runCheck's doc comment, which currently hardcodes `ip address`):

```go
// sshArgs builds the ssh argv for c: batch-mode options, the target host,
// and the remote command for the check's type. Unknown or empty types fall
// back to the default so a zero-value Check still runs a sane command.
func sshArgs(c Check, connectTimeoutSeconds int) []string {
	command, ok := checkCommands[c.Type]
	if !ok {
		command = checkCommands[defaultCheckType]
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeoutSeconds),
		"--", c.Hostname, command,
	}
}

// runCheck runs the check's remote command via ssh (see checkCommands) and
// confirms the expected ip is present in the output. BatchMode avoids
// password prompts so an unreachable or auth-failing host fails fast rather
// than hanging. ~/.ssh/config is honoured because we invoke the real ssh
// binary.
func runCheck(ctx context.Context, timeout time.Duration, c Check) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	seconds := max(int(timeout.Seconds()), 1)
	cmd := exec.CommandContext(ctx, "ssh", sshArgs(c, seconds)...)
```

(The rest of `runCheck` — the `cmd.Output()` error handling and `ipPresent` call — is unchanged. The final error message `"ip %s not found in ` + "`ip address`" + ` output"` stays as-is: `ip address` output is present for both types.)

Note this changes the remote command from two argv words (`"ip", "address"`) to one (`"ip address"`) — behaviourally identical, since ssh joins remaining args with spaces into a single remote command string either way.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: dispatch remote check command by check type in runCheck

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: CLI flags and main wiring

**Files:**
- Modify: `main.go` (CLI struct ~lines 31-37; main ~lines 90-112)

**Interfaces:**
- Consumes: `loadConfig` (Task 1), `run(cli, config, log, r)` (Task 2).
- Produces: `CLI.Config string` field; `-c/--config` and `-C/--concurrency` flags.

- [ ] **Step 1: Update the CLI struct**

In `main.go`, add `Config` and change Concurrency's short flag to `C`:

```go
// CLI holds the command-line configuration.
type CLI struct {
	Config      string        `kong:"short='c',placeholder='PATH',help='Path to a YAML config file mapping hostnames to per-host settings (see README).'"`
	Concurrency int           `kong:"short='C',default='8',help='Number of ssh checks to run in parallel.'"`
	Timeout     time.Duration `kong:"short='t',default='10s',help='Per-check ssh timeout.'"`
	Strip       string        `kong:"short='s',xor='strip',placeholder='DOMAIN',help='Strip the given domain suffix from each hostname before the ssh check (a leading dot is added if absent, so example.com strips .example.com from foo.example.com => foo).'"`
	StripAll    bool          `kong:"short='S',name='strip-all',xor='strip',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
	Verbose     bool          `kong:"short='v',help='Enable verbose (debug) logging.'"`
}
```

- [ ] **Step 2: Wire config loading into main**

In `main`, after the logger is created and before the `run` call, load the config; replace `run(cli, nil, ...)` with the loaded map:

```go
	cli.Concurrency = max(cli.Concurrency, 1)

	var config map[string]HostConfig
	if cli.Config != "" {
		var err error
		config, err = loadConfig(cli.Config)
		if err != nil {
			log.Error("loading config", "err", err)
			os.Exit(1)
		}
	}

	os.Exit(run(cli, config, log, os.Stdin))
```

- [ ] **Step 3: Build and run the test suite**

Run: `go build ./... && go test ./...`
Expected: builds clean, all tests PASS.

- [ ] **Step 4: Smoke-test the flags end-to-end**

Run: `go run . --help 2>&1 | grep -E -- '-c, --config|-C, --concurrency'`
Expected: both lines present (`-c, --config=PATH` and `-C, --concurrency=8`).

Run (scratchpad dir per session; any temp dir works):

```bash
d=$(mktemp -d)
printf 'web1.example.com:\n  type: aws\n' > "$d/config.yml"
printf '' | go run . -c "$d/config.yml"; echo "exit=$?"
```

Expected: `all checks passed` with `checks=0`, `exit=0`.

```bash
printf 'web1.example.com:\n  type: gcp\n' > "$d/bad.yml"
printf '' | go run . -c "$d/bad.yml"; echo "exit=$?"
```

Expected: an ERR `loading config` line mentioning `unknown type "gcp"`, `exit=1`, and no run summary (no checks ran).

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: add -c/--config flag, move --concurrency short flag to -C

Config errors (missing file, bad YAML, unknown key or type) are fatal
at startup via slog.Error + exit 1, before any checks run.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: README documentation

**Files:**
- Modify: `README.md` (insert new section between "Usage" and "Author")

**Interfaces:**
- Consumes: flag names and semantics from Task 4.

- [ ] **Step 1: Add the Configuration file section**

Insert after the Usage section (before "Author"):

```markdown
Configuration file
------------------

Some checks need per-host settings — most notably AWS EC2 instances,
whose public IP is a 1:1 NAT mapping held in AWS infrastructure rather
than configured on the instance, so it never appears in `ip address`
output. Pass a YAML config file with `-c`/`--config`, keyed by hostname
*as it appears on stdin* (before any `-s`/`-S` stripping):

    web1.example.com:
      type: aws
    web2.example.com:
      type: iproute2

Supported per-host keys:

- `type`: the check type — `iproute2` (the default: run `ip address`
  and look for the expected ip) or `aws` (additionally query the EC2
  Instance Metadata Service for the instance's public IPv4, so both
  private and public addresses can be verified).

Hosts absent from the config file (or with no `type`) use `iproute2`.
Config entries for hosts not present on stdin are ignored, so one
config file can cover a superset of any given input.
```

- [ ] **Step 2: Verify the suite still passes**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document -c/--config per-host check types in README

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```
