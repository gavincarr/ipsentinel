# Design: soft/hard ssh error classification with a retry pass

Date: 2026-07-22
Status: approved

## Problem

Every failed check currently alerts immediately (main.go:146-149). But ssh
failures are not all equal:

- Some are **hard** and definitive — no retry will fix them. `Permission
  denied` (auth), `Host key verification failed`, `Name or service not known`
  (DNS), and our own `ip … not found` mismatch (the host answered correctly,
  the IP is simply gone).
- Some are **soft** and transient — a second attempt moments later usually
  succeeds. `kex_exchange_identification: Connection closed by remote host`,
  `Connection reset by peer`, and per-check timeouts fall here.

Alerting on transient blips creates noise. We want to alert hard failures
immediately, but collect soft failures and give them one or more retry passes
before deciding they are real.

## Requirements

- Classify each check failure as **soft** (retryable) or **hard**.
- Unknown/unrecognised errors are treated as **hard** (conservative): only an
  explicit whitelist of known-transient patterns is retried.
- Hard failures alert immediately, exactly as today.
- Soft failures are collected and retried in up to N passes with exponential
  backoff. A soft failure only alerts if it survives every pass.
- A soft failure that recovers on a later pass counts as a success — no alert,
  no failure count.
- Per-check ssh timeouts are classified **soft**.
- Configurable: `-r/--retries` (pass count) and `--retry-delay` (base backoff).
- The retry orchestration must be unit-testable without invoking real ssh.

## Design

### Classification: `retryable(err error) bool`

ssh collapses almost every connection failure into exit code 255, so the exit
code carries no signal; the human-readable stderr is the only discriminator.
`runCheck` already surfaces that text (`ssh failed: <stderr>`, `ssh timed out
after …`). Classification is therefore a case-insensitive substring match of
the error's message against a whitelist of soft patterns:

```go
// softErrorPatterns are the known-transient ssh failure signatures. A check
// error matching any of these (case-insensitive substring) is retried; every
// other failure — including unrecognised ones — is treated as hard and
// alerted immediately.
var softErrorPatterns = []string{
    "ssh timed out after",         // our own context-deadline message
    "kex_exchange_identification", // early key-exchange abort by the server
    "connection closed by remote host",
    "connection reset by peer",
    "connection timed out",        // ssh's own network-level timeout
}

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

Deliberately **not** soft (fall through to hard): `Permission denied`, `Host
key verification failed`, `Name or service not known` / `Could not resolve
hostname`, `No route to host`, `Connection refused` (a refused port is usually
a real "nothing is listening" answer), and the `ip … not found` mismatch. The
slice is the single, easily-edited tuning point.

### Pass runner: `runPass`

Extract the current worker fan-out (main.go:141-159) into a reusable function
that runs one concurrent pass over a set of checks:

```go
// softFail pairs a check with the (retryable) error from its most recent
// attempt, so a survivor can be alerted with its last real error.
type softFail struct {
    c   Check
    err error
}

// checker runs a single check; runCheck in production, a fake in tests. This
// seam makes the retry loop testable without invoking real ssh.
type checker func(ctx context.Context, timeout time.Duration, c Check) error

// runPass runs every check in checks concurrently (bounded by cli.Concurrency).
// A hard failure is alerted and counted in failures immediately. A retryable
// failure is returned in the slice — NOT yet alerted or counted — for the
// caller to retry. Successful checks are logged at debug.
func runPass(ctx context.Context, cli CLI, checks []Check, run checker,
    alerter Alerter, log *slog.Logger, failures *atomic.Int64) []softFail
```

Internally identical to today's loop (a `jobs` channel, `cli.Concurrency`
workers, `wg.Wait()`), except the per-check branch becomes:

- `run(...) == nil` → `log.Debug("ok", …)` as now.
- error and `!retryable(err)` → `alerter.Alert(c, "check failed", err)` and
  `failures.Add(1)`, as now.
- error and `retryable(err)` → append `{c, err}` to a mutex-guarded soft slice;
  no alert, no count yet.

### Retry loop in `run()`

```go
checkFn := runCheck // the checker seam; tests substitute a fake
soft := runPass(ctx, cli, checks, checkFn, alerter, log, &failures)
for attempt := 1; attempt <= cli.Retries && len(soft) > 0; attempt++ {
    delay := cli.RetryDelay * time.Duration(1<<(attempt-1)) // base·2^(N-1)
    if delay > 0 {
        time.Sleep(delay)
    }
    log.Info("retry pass", "attempt", attempt, "pending", len(soft))
    retry := make([]Check, len(soft))
    for i, sf := range soft {
        retry[i] = sf.c
    }
    soft = runPass(ctx, cli, retry, checkFn, alerter, log, &failures)
}
// survivors of the final pass: now genuinely failed.
for _, sf := range soft {
    alerter.Alert(sf.c, "check failed (after retries)", sf.err)
    failures.Add(1)
}
```

`cli.Retries == 0` skips the loop entirely — a soft failure from the initial
pass falls straight through to the survivor alert, preserving today's
alert-immediately behaviour when retries are disabled.

### Success accounting

The existing arithmetic (main.go:161-168) is unchanged:

```go
successes := len(checks) - (int(n) - parseFailures)
```

`failures` still counts each real failure exactly once — hard failures inside
`runPass`, plus final-pass survivors. A soft failure that recovers is never
counted, so it correctly lands in `successes`. Exit code stays 0 iff every
check ultimately passed.

### CLI flags

```go
Retries    int           `kong:"short='r',default='2',help='Number of retry passes for transient (soft) ssh failures.'"`
RetryDelay time.Duration `kong:"name='retry-delay',default='5s',help='Base backoff before the first retry pass; pass N waits delay·2^(N-1).'"`
```

- `-r/--retries` default **2** (initial run + up to 2 retries).
- `--retry-delay` default **5s**, long-only. Backoff schedule at defaults:
  5s before pass 1, 10s before pass 2. `0` disables sleeping (used by tests).
- `cli.Retries = max(cli.Retries, 0)` guard in `main`, mirroring the existing
  `Concurrency` clamp.

### Alerting behaviour change (intended)

Today: every failure alerts immediately with reason `check failed`.
After: **hard** failures still alert immediately (`check failed`); **soft**
failures alert only if they survive all passes, with reason `check failed
(after retries)`. This is the point of the feature; noted here because it
changes log output and the timing of alerts.

## Error handling summary

| Failure | Classification | Behaviour |
|---|---|---|
| `Permission denied`, host-key, DNS, `No route to host`, `Connection refused` | hard | alert immediately (`check failed`) |
| `ip … not found` mismatch | hard | alert immediately (`check failed`) |
| unrecognised error message | hard | alert immediately (`check failed`) |
| `kex_exchange_identification`, `Connection closed/reset` | soft | retried; alert only if it survives all passes |
| per-check ssh timeout | soft | retried; alert only if it survives all passes |
| soft failure that recovers on a later pass | — | no alert, counts as success |

## Testing

- `TestRetryable` — table of representative real ssh messages (both examples
  from the request plus the others) asserting soft/hard, including
  case-insensitivity and the deliberately-hard cases (`Permission denied`,
  `ip … not found`).
- `TestRetryLoop` (via the `checker` seam, `--retry-delay 0`):
  - soft-fails twice then succeeds → checker invoked 3×, zero alerts, counted
    as success.
  - hard-fails once → checker invoked 1×, one immediate alert, never retried.
  - soft-fails on every pass → checker invoked `1+retries` times, exactly one
    `check failed (after retries)` alert.
  - `Retries == 0` with a soft failure → one alert, no retry.
- Existing tests are unaffected (parseInput/sshArgs signatures unchanged).

## Documentation

README gains a short "Retries" note: soft (transient) ssh failures —
connection resets, early kex aborts, timeouts — are retried up to `--retries`
times with exponential backoff before alerting, while hard failures (auth, DNS,
wrong IP) alert immediately. Document `-r/--retries` and `--retry-delay`.

## Alternatives considered

- **Typed errors** (`runCheck` returns an error carrying a `retryable` bool):
  rejected — `runCheck` already flattens ssh stderr into a formatted string, so
  a typed error would re-derive the same signal with more plumbing and no gain.
- **Exit-code classification**: not viable — ssh returns 255 for nearly every
  connection failure.
- **Unknown = soft** (whitelist hard patterns, retry everything else): rejected
  per the conservative posture — retrying a definitive wrong-IP or auth failure
  wastes attempts and delays a real alert.
- **`Connection refused` as soft**: left hard by default; a refused port is
  usually a genuine "service absent" answer. One line to move if experience
  says otherwise.
