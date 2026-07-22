# SSH Error Classification with Retry Pass — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify ssh check failures as soft (transient/retryable) or hard (definitive); alert hard failures immediately, but collect soft failures and retry them in up to N passes with exponential backoff before alerting.

**Architecture:** A pure `retryable(err)` classifier substring-matches the error message against a whitelist of known-transient ssh signatures (unknown ⇒ hard). The worker fan-out becomes `runPass`, which alerts hard failures immediately and returns soft ones. A new `runChecks` drives the initial pass plus the retry loop and owns the success/exit tally. A `checker` function seam lets the retry loop be unit-tested without real ssh.

**Tech Stack:** Go (stdlib only — `context`, `sync`, `sync/atomic`, `time`, `strings`, `slog`; kong for flags). No new dependencies.

## Global Constraints

- Preferred language Go; route all logging through `slog` (never stdlib `log`). User-facing fatal output uses `slog.Error` + `os.Exit(1)`.
- Conventional Commits for every commit. Do **not** push (commit locally only).
- Unknown/unrecognised errors classify as **hard** (conservative whitelist posture).
- Timeouts (`ssh timed out after …`) classify as **soft**.
- Match is case-insensitive substring against `softErrorPatterns`.
- Defaults: `-r/--retries` = `2`; `--retry-delay` = `5s`; backoff for pass N = `delay·2^(N-1)`; `--retry-delay 0` disables sleeping.
- Alert reasons: hard/immediate = `"check failed"`; soft survivor after all passes = `"check failed (after retries)"`.
- No new imports needed — every package listed above is already imported in `main.go`.
- Go 1.25+ `wg.Go(func(){…})` is already used in this codebase; keep that style.

---

### Task 1: `retryable` classifier

**Files:**
- Modify: `main.go` (add `softErrorPatterns` var + `retryable` func, near `runCheck` at main.go:257-285)
- Test: `main_test.go` (add `TestRetryable`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `var softErrorPatterns []string`
  - `func retryable(err error) bool` — reports whether `err` is a known-transient ssh failure worth retrying. `nil` ⇒ `false`.

- [ ] **Step 1: Write the failing test**

Add to `main_test.go`:

```go
func TestRetryable(t *testing.T) {
	soft := []string{
		"ssh timed out after 10s",
		"ssh failed: kex_exchange_identification: Connection closed by remote host",
		"ssh failed: kex_exchange_identification: read: Connection reset by peer",
		"ssh failed: Connection closed by 10.0.0.1 port 22", // case-insensitive match on "connection closed by"
		"ssh failed: connect to host web1 port 22: Connection timed out",
	}
	hard := []string{
		"ssh failed: Permission denied (publickey).",
		"ssh failed: Host key verification failed.",
		"ssh failed: ssh: Could not resolve hostname web1: Name or service not known",
		"ssh failed: connect to host web1 port 22: No route to host",
		"ssh failed: connect to host web1 port 22: Connection refused",
		"ip 10.0.0.1 not found in `ip address` output",
	}
	for _, s := range soft {
		if !retryable(fmt.Errorf("%s", s)) {
			t.Errorf("retryable(%q) = false, want true (soft)", s)
		}
	}
	for _, h := range hard {
		if retryable(fmt.Errorf("%s", h)) {
			t.Errorf("retryable(%q) = true, want false (hard)", h)
		}
	}
	if retryable(nil) {
		t.Error("retryable(nil) = true, want false")
	}
}
```

This needs `fmt` in `main_test.go`. Add it to the import block (`"fmt"`) — current imports are `slices`, `strings`, `testing`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestRetryable`
Expected: FAIL — `undefined: retryable` (compile error).

- [ ] **Step 3: Write minimal implementation**

Add to `main.go`, immediately above `runCheck` (main.go:257):

```go
// softErrorPatterns are the known-transient ssh failure signatures. A check
// error whose message contains any of these (case-insensitive) is retried;
// every other failure — including unrecognised ones — is treated as hard and
// alerted immediately. "connection closed by" is intentionally broader than
// the "remote host" variant so it also catches ssh's "Connection closed by
// <addr> port 22" form; both are transient handshake aborts.
var softErrorPatterns = []string{
	"ssh timed out after",         // our own context-deadline message
	"kex_exchange_identification", // early key-exchange abort by the server
	"connection closed by",
	"connection reset by peer",
	"connection timed out", // ssh's own network-level timeout
}

// retryable reports whether err is a known-transient ssh failure worth a
// retry pass. Unknown errors return false (hard) by design; see
// softErrorPatterns for the whitelist and the design doc for the rationale.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, p := range softErrorPatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestRetryable -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: classify soft (retryable) vs hard ssh failures

Add retryable() and the softErrorPatterns whitelist. Unknown errors are
hard by design; known-transient signatures (kex abort, connection
reset/closed, timeouts) are soft."
```

---

### Task 2: `runPass`, `runChecks`, retry loop, and CLI flags

**Files:**
- Modify: `main.go` — add `softFail` type, `checker` type, `runPass`, `runChecks`; extract the fan-out+tally out of `run` (currently main.go:138-168) into these; add `Retries`/`RetryDelay` to `CLI` (main.go:31-38); add clamp in `main` (main.go:112).
- Test: `main_test.go` — add a `fakeChecker` helper, `TestRunPass`, `TestRetryLoop`.

**Interfaces:**
- Consumes: `retryable(err error) bool` (Task 1); existing `Check`, `Alerter`, `LogAlerter`, `runCheck(ctx, timeout, Check) error`, `parseInput`.
- Produces:
  - `type softFail struct { c Check; err error }`
  - `type checker func(ctx context.Context, timeout time.Duration, c Check) error`
  - `func runPass(ctx context.Context, cli CLI, checks []Check, checkFn checker, alerter Alerter, log *slog.Logger, failures *atomic.Int64) []softFail`
  - `func runChecks(ctx context.Context, cli CLI, checks []Check, parseFailures int, alerter Alerter, log *slog.Logger, checkFn checker) int`
  - `CLI.Retries int`, `CLI.RetryDelay time.Duration`

- [ ] **Step 1: Add the CLI flags**

In the `CLI` struct (main.go:31-38), add after `Timeout`:

```go
	Retries    int           `kong:"short='r',default='2',help='Number of retry passes for transient (soft) ssh failures.'"`
	RetryDelay time.Duration `kong:"name='retry-delay',default='5s',help='Base backoff before the first retry pass; pass N waits delay*2^(N-1).'"`
```

In `main` (main.go:112), add a clamp beside the existing `Concurrency` one:

```go
	cli.Concurrency = max(cli.Concurrency, 1)
	cli.Retries = max(cli.Retries, 0)
```

- [ ] **Step 2: Write the failing tests**

Add to `main_test.go`. First a concurrency-safe fake checker seam:

```go
// fakeChecker returns scripted errors per hostname: the i-th call for a host
// returns scripts[host][i] (nil once the script is exhausted → success). Safe
// for concurrent use by runPass workers.
type fakeChecker struct {
	mu      sync.Mutex
	scripts map[string][]error
	calls   map[string]int
}

func newFakeChecker(scripts map[string][]error) *fakeChecker {
	return &fakeChecker{scripts: scripts, calls: map[string]int{}}
}

func (f *fakeChecker) check(_ context.Context, _ time.Duration, c Check) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls[c.Hostname]
	f.calls[c.Hostname]++
	s := f.scripts[c.Hostname]
	if i < len(s) {
		return s[i]
	}
	return nil
}

func softErr() error { return fmt.Errorf("ssh timed out after 10s") }
func hardErr() error { return fmt.Errorf("ssh failed: Permission denied (publickey).") }

// testCLI returns a CLI with sleeping disabled so retry tests run instantly.
func testCLI(retries int) CLI {
	return CLI{Concurrency: 4, Timeout: time.Second, Retries: retries, RetryDelay: 0}
}
```

Then `TestRunPass` (single pass: hard alerts + counts immediately, soft is returned only):

```go
func TestRunPass(t *testing.T) {
	checks := []Check{
		{Hostname: "ok"},
		{Hostname: "soft"},
		{Hostname: "hard"},
	}
	fc := newFakeChecker(map[string][]error{
		"soft": {softErr()},
		"hard": {hardErr()},
	})
	var alerter captureAlerter
	var failures atomic.Int64
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	soft := runPass(context.Background(), testCLI(2), checks, fc.check, &alerter, log, &failures)

	if len(soft) != 1 || soft[0].c.Hostname != "soft" {
		t.Fatalf("soft = %+v, want one entry for host \"soft\"", soft)
	}
	if got := failures.Load(); got != 1 {
		t.Errorf("failures = %d, want 1 (hard only)", got)
	}
	if len(alerter.alerts) != 1 || alerter.alerts[0].reason != "check failed" {
		t.Errorf("alerts = %+v, want one \"check failed\"", alerter.alerts)
	}
}
```

Then `TestRetryLoop` (whole `runChecks` orchestration):

```go
func TestRetryLoop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name          string
		retries       int
		script        []error // for the single host "h"
		wantCalls     int
		wantAlerts    int
		wantReason    string // reason of the (single) alert, if wantAlerts == 1
		wantExit      int
	}{
		{"soft twice then recovers", 2, []error{softErr(), softErr()}, 3, 0, "", 0},
		{"hard never retried", 2, []error{hardErr()}, 1, 1, "check failed", 1},
		{"soft never recovers", 2, []error{softErr(), softErr(), softErr()}, 3, 1, "check failed (after retries)", 1},
		{"retries zero", 0, []error{softErr()}, 1, 1, "check failed (after retries)", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := newFakeChecker(map[string][]error{"h": tt.script})
			var alerter captureAlerter
			exit := runChecks(context.Background(), testCLI(tt.retries),
				[]Check{{Hostname: "h"}}, 0, &alerter, log, fc.check)

			if fc.calls["h"] != tt.wantCalls {
				t.Errorf("calls = %d, want %d", fc.calls["h"], tt.wantCalls)
			}
			if len(alerter.alerts) != tt.wantAlerts {
				t.Fatalf("alerts = %d, want %d: %+v", len(alerter.alerts), tt.wantAlerts, alerter.alerts)
			}
			if tt.wantAlerts == 1 && alerter.alerts[0].reason != tt.wantReason {
				t.Errorf("alert reason = %q, want %q", alerter.alerts[0].reason, tt.wantReason)
			}
			if exit != tt.wantExit {
				t.Errorf("exit = %d, want %d", exit, tt.wantExit)
			}
		})
	}
}
```

These tests need `context`, `io`, `log/slog`, `sync`, `sync/atomic`, and `time` in `main_test.go` (current imports: `fmt` from Task 1, `slices`, `strings`, `testing`). Add the missing ones.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./... -run 'TestRunPass|TestRetryLoop'`
Expected: FAIL — `undefined: runPass`, `undefined: runChecks` (compile error).

- [ ] **Step 4: Add the types**

In `main.go`, add just above `runCheck` (after the `retryable` block from Task 1):

```go
// softFail pairs a check with the retryable error from its most recent
// attempt, so a survivor of the retry loop can be alerted with its last
// real error.
type softFail struct {
	c   Check
	err error
}

// checker runs a single check. runCheck is the production implementation;
// tests substitute a fake so the retry loop can be exercised without ssh.
type checker func(ctx context.Context, timeout time.Duration, c Check) error
```

- [ ] **Step 5: Add `runPass`**

In `main.go`, add after `runChecks` will live — place it just above `runCheck`:

```go
// runPass runs every check in checks concurrently (bounded by cli.Concurrency).
// A hard (non-retryable) failure is alerted and counted in failures at once;
// a retryable failure is returned in the slice — not yet alerted or counted —
// for the caller to retry. Successful checks are logged at debug.
func runPass(ctx context.Context, cli CLI, checks []Check, checkFn checker,
	alerter Alerter, log *slog.Logger, failures *atomic.Int64) []softFail {
	var (
		mu   sync.Mutex
		soft []softFail
	)
	jobs := make(chan Check)
	var wg sync.WaitGroup
	for range cli.Concurrency {
		wg.Go(func() {
			for c := range jobs {
				err := checkFn(ctx, cli.Timeout, c)
				if err == nil {
					log.Debug("ok", "hostname", c.Hostname, "ip", c.IP)
					continue
				}
				if retryable(err) {
					mu.Lock()
					soft = append(soft, softFail{c, err})
					mu.Unlock()
					continue
				}
				alerter.Alert(c, "check failed", err)
				failures.Add(1)
			}
		})
	}
	for _, c := range checks {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	return soft
}
```

- [ ] **Step 6: Add `runChecks`**

In `main.go`, add above `runPass`:

```go
// runChecks runs the initial pass over checks, then up to cli.Retries further
// passes over the checks that failed with a retryable error, sleeping
// cli.RetryDelay*2^(N-1) before pass N (skipped when the delay is 0). Any soft
// failure still failing after the last pass is alerted (reason "check failed
// (after retries)") and counted. Returns the process exit code: 0 iff every
// check ultimately passed. parseFailures pre-seeds the failure count and is
// excluded from the success tally.
func runChecks(ctx context.Context, cli CLI, checks []Check, parseFailures int,
	alerter Alerter, log *slog.Logger, checkFn checker) int {
	var failures atomic.Int64
	failures.Add(int64(parseFailures))

	soft := runPass(ctx, cli, checks, checkFn, alerter, log, &failures)
	for attempt := 1; attempt <= cli.Retries && len(soft) > 0; attempt++ {
		if delay := cli.RetryDelay * time.Duration(1<<(attempt-1)); delay > 0 {
			time.Sleep(delay)
		}
		log.Info("retry pass", "attempt", attempt, "pending", len(soft))
		retry := make([]Check, len(soft))
		for i, sf := range soft {
			retry[i] = sf.c
		}
		soft = runPass(ctx, cli, retry, checkFn, alerter, log, &failures)
	}
	for _, sf := range soft {
		alerter.Alert(sf.c, "check failed (after retries)", sf.err)
		failures.Add(1)
	}

	n := failures.Load()
	successes := len(checks) - (int(n) - parseFailures)
	if n > 0 {
		log.Info("finished with failures", "checks", len(checks), "successes", successes, "failures", n)
		return 1
	}
	log.Info("all checks passed", "checks", len(checks), "successes", successes)
	return 0
}
```

- [ ] **Step 7: Rewrite `run` to delegate**

Replace the body of `run` (main.go:129-169) so it only parses and delegates. The failure fan-out and tally now live in `runChecks`:

```go
// run reads checks from r, runs them (with retries for transient failures),
// and returns the process exit code (0 = all passed, 1 = one or more failures).
func run(cli CLI, config map[string]HostConfig, log *slog.Logger, r io.Reader) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.StripAll, cli.Strip, config)
	if parseFailures > 0 {
		log.Warn("input had malformed lines", "count", parseFailures)
	}
	log.Debug("parsed input", "checks", len(checks))

	return runChecks(context.Background(), cli, checks, parseFailures, alerter, log, runCheck)
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./... -run 'TestRunPass|TestRetryLoop' -v`
Expected: PASS (all `TestRetryLoop` subtests and `TestRunPass`).

- [ ] **Step 9: Run the full suite + vet**

Run: `go vet ./... && go test ./...`
Expected: PASS — no regressions in the existing parseInput/sshArgs/etc. tests.

- [ ] **Step 10: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: retry transient ssh failures with exponential backoff

Extract the worker fan-out into runPass (hard failures alert immediately,
soft ones are returned) and add runChecks to drive up to --retries passes
with delay*2^(N-1) backoff. Soft failures alert only if they survive every
pass. Add -r/--retries (default 2) and --retry-delay (default 5s); a
checker seam makes the loop testable without real ssh."
```

---

### Task 3: Document retries in the README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the `-r/--retries` and `--retry-delay` flags (Task 2).
- Produces: nothing (docs only).

- [ ] **Step 1: Read the README to find the flags/usage section**

Run: `sed -n '1,120p' README.md` (or open it) to locate where flags and behaviour are described, so the new note matches the existing structure and tone.

- [ ] **Step 2: Add a "Retries" subsection**

Add prose covering, in the README's existing voice:

```markdown
## Retries

Not every ssh failure means a host has genuinely lost its IP. Transient
failures — an early handshake abort
(`kex_exchange_identification: Connection closed by remote host`), a
connection reset, or a per-check timeout — are collected and retried before
they alert. Hard failures — authentication (`Permission denied`), host-key
mismatch, DNS resolution, or a wrong/missing IP — are definitive and alert
immediately.

Soft failures are retried up to `--retries` times (default 2) with
exponential backoff: pass N waits `--retry-delay * 2^(N-1)` (default base
`5s`, so 5s then 10s). A soft failure alerts only if it still fails after
the last pass; one that recovers on a retry is a success. Set `--retries 0`
to disable retries and alert every failure immediately.

- `-r, --retries` — number of retry passes for transient failures (default 2).
- `--retry-delay` — base backoff before the first retry pass (default 5s).
```

Adjust heading level / placement to match the surrounding README.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document --retries/--retry-delay and soft/hard failures"
```

---

## Self-Review

**Spec coverage:**
- Classify soft/hard, unknown ⇒ hard → Task 1 (`retryable` + whitelist).
- Hard alerts immediately → Task 2 `runPass` (`"check failed"`).
- Soft collected + retried N passes, backoff → Task 2 `runChecks`.
- Soft survivor alerts once (`"check failed (after retries)"`); recovered soft = success → Task 2 `runChecks` + `TestRetryLoop` cases.
- Timeout = soft → `"ssh timed out after"` in `softErrorPatterns` (Task 1), asserted in `TestRetryable`.
- `-r/--retries`, `--retry-delay`, `0` disables sleep → Task 2 Step 1 + `testCLI`/`retries zero` case.
- Success accounting unchanged / exit code → Task 2 `runChecks` tally, asserted via `wantExit`.
- Testable without real ssh → `checker` seam + `fakeChecker` (Task 2).
- README note → Task 3.

**Placeholder scan:** none — every code and test step is complete; the only `sed`/read step (Task 3 Step 1) is a locate-context action, not a deferred implementation.

**Type consistency:** `checker`/`checkFn`, `softFail{c, err}`, `runPass`, `runChecks`, `softErrorPatterns`, `retryable`, `CLI.Retries`/`CLI.RetryDelay` are spelled identically across tasks and match the spec. `runPass`/`runChecks` parameter order is identical everywhere it appears. `captureAlerter` (existing) already records `reason`, which `TestRunPass`/`TestRetryLoop` rely on.

**Note vs spec:** the spec listed `"connection closed by remote host"`; the plan broadens it to `"connection closed by"` to also catch ssh's `Connection closed by <addr> port 22` form (both transient). Documented inline in the `softErrorPatterns` comment.
