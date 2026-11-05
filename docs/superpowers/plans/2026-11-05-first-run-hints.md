# First-run hints — implementation plan

Spec: none written; the design was agreed in chat (2026-11-05) and is
restated in full under "Design" below. Treat "Design" as the spec.

## Why

`--connect-default` now defaults to `ip`, which is the stronger check,
but a new user's first `check` run fails every connect: ip host whose key
isn't recorded under its ip name yet (`[ip]:port`, or `ip` on 22) with
`ssh failed: Host key verification failed.` A wall of those alarming,
unexplained alerts could frighten new users off. `ipsentinel known-hosts`
fixes most of them, but nothing tells the user that.

## Design

1. **Specific per-host alert.** A connect: ip check whose ssh error is an
   *unknown* host key is alerted with reason
   `host key not recorded for ip` instead of `check failed` (the err
   stays as now). A *changed* or *revoked* key must never be classed as
   unknown: those are the real alarms and keep reason `check failed`.
   Classification is by ssh's stderr (carried in the error text):
   unknown iff it contains `Host key verification failed`
   (case-insensitive) and does **not** contain `@@@` — OpenSSH prints an
   `@@@…@@@` banner (`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`,
   `WARNING: REVOKED HOST KEY DETECTED!`, `WARNING: POSSIBLE DNS
   SPOOFING DETECTED!`) for every changed/revoked/mismatch case and never
   for an unknown key. Known unknown-key forms:
   - BatchMode with the default StrictHostKeyChecking=ask (verified on
     the dev box, OpenSSH 9.6): stderr is just
     `Host key verification failed.`
   - StrictHostKeyChecking=yes: `No ED25519 host key is known for
     [192.0.2.1]:2222 and you have requested strict checking.` then
     `Host key verification failed.`
   connect: ssh_config checks are not reclassified (known-hosts can't
   help them).
2. **Diagnose, don't guess.** After the run, each check alerted as an
   unknown host key is diagnosed with the same logic `known-hosts` uses
   (ssh -G + ssh-keygen -F on local files; connects to nothing): either
   *fixable* (known-hosts would print lines for it), *no known key*
   (no key under the host's usual name), or *other* (anything else:
   lookup error, already recorded, alias, revoked, foreign ip key).
3. **Closing summary, last thing on screen** (after the existing
   `finished with failures` line), at Warn so it shows at the default
   level, one log record per line:

       N of M connect: ip hosts failed: host key not recorded under the ip yet
       F can be fixed with: ipsentinel known-hosts -c ipsentinel.yml -s example.com >> /root/.ssh/known_hosts
       K have no known key at all; add them by hand, see README "connect: ip"
       to check by hostname instead, pass --connect-default=ssh_config

   - N = connect: ip checks alerted as unknown host key; M = connect: ip
     checks in the run (after parsing).
   - Line 1 whenever N >= 1. Line 2 when F >= 1, line 3 when K >= 1
     (omit a line whose count is 0). "other" hosts get no line of their
     own (they're still in N).
   - Line 4 (the ssh_config suggestion) only when it looks like a first
     run: N >= 3 **and** 2*N >= M. Constants, not flags.
   - The suggested command echoes the user's own relevant flags so it
     can be pasted: `-c <config>` if given, `--connect-default=<v>` if
     not the default, `-s <domain>` or `-S` if given. Never `-i` or the
     other check-only flags. Shell-quote any value containing
     characters outside `[A-Za-z0-9._/:=@+-]` (single quotes).
   - `>> <file>` is appended when every fixable host's ip side has the
     same first user known_hosts file (from ssh -G); otherwise end with
     `and append its output to your known_hosts` instead.
4. **known-hosts closing line.** When known-hosts printed at least one
   line, log at Warn (so it shows by default):
   `printed N known_hosts lines for <file>` where `<file>` is the ip
   side's first user known_hosts file if all printed hosts agree, else
   `printed N known_hosts lines; they belong in each host's UserKnownHostsFile`.
   Keep the existing Info `known_hosts lines printed` only if it isn't
   now redundant (it is when lines > 0; keep it for the zero case, or
   replace with a `nothing new to print` Info).
5. **README "First run" section** near the top (after Usage): with
   connect: ip the default, run `known-hosts`, review and append its
   output, then run `check`; mention the end-of-run hint and
   `--connect-default=ssh_config` as the alternative. Also document the
   new alert reason and the closing hint where alerts/output are
   described, and the known-hosts closing line.

Out of scope: changing alert semantics for cron (every failing host is
still alerted individually), retries (unknown host keys are hard
failures, never retried), connect: ssh_config hosts.

## Global Constraints

- Go, existing module; no new dependencies; `*slog.Logger` only (never
  stdlib `log`); stdout untouched by `check`, and only known_hosts lines
  on known-hosts' stdout.
- Match existing style: doc comments explaining why, table-driven tests,
  `gofmt`, `go vet ./...`, `go test ./...` clean. Tests never depend on
  the developer's ~/.ssh: fake ssh -G, real ssh-keygen over t.TempDir()
  files (skip if ssh-keygen missing), as knownhosts_test.go does.
- Existing log messages quoted in README.md must not change wording
  (`no known host key for host; add it by hand, see README`,
  `ip already has a different host key; not adding`,
  `host key revoked for host; not adding`, `ssh -G failed`,
  `looking up host key failed`, `looking up ip key failed`,
  `user known_hosts files differ between host and ip; …`,
  `no connect: ip hosts in input; nothing to do (do they all set connect: ssh_config?)`).
- Commits: Conventional Commits with a why-body, ending with the trailer
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Commit
  only; never push.

## Task 1: extract the known-hosts decision; known-hosts closing line

Files: knownhosts.go, knownhosts_test.go.

Split `knownHostsFor` into a side-effect-free decision and the
logging/printing that acts on it, so `check` (Task 2) can reuse the
decision silently. Suggested shape (names are suggestions):

    type hostKeyStatus int // aliased, recorded, addable, noHostKey, revoked, foreignIPKey, lookupError
    type hostKeyPlan struct {
        status           hostKeyStatus
        hostName, ipName string    // plain (unhashed) names
        ipUserFile       string    // ip side's first user known_hosts file, "" if none
        userFilesDiffer  bool      // ip side's user files != host side's
        hash             bool      // ip side HashKnownHosts yes
        add              []hostKey // addable: keys to print, in order
        err              error     // lookupError: the cause
        errSide, errMsg  string    // which lookup failed, for the existing log messages
    }
    func planHostKeys(ctx context.Context, c Check, env knownHostsEnv, printed map[string][]hostKey) hostKeyPlan

`planHostKeys` must tolerate a nil `printed`. `knownHostsFor` keeps its
exact current observable behaviour (same messages, attrs, levels, exit
codes, output), now implemented as plan → log per status → print
`add` (hashing per `hash`) → update `printed`. The existing
knownhosts tests must pass unchanged except where design point 4
changes the end-of-run log; add direct unit tests of `planHostKeys`
for each status.

Then implement design point 4 (closing line) in `runKnownHosts`, with
tests (one file; differing files; zero lines).

## Task 2: classify, alert and hint in check

Files: main.go (runPass/runChecks/run), a new hints.go if it keeps
main.go focused, main_test.go and/or hints_test.go.

- `unknownHostKey(err error) bool` per design point 1; table-test it
  with the forms above plus a changed-key banner, a revoked banner, a
  non-host-key error, and nil.
- In `runPass`, a hard failure of a connect: ip check with
  `unknownHostKey(err)` is alerted with reason
  `host key not recorded for ip` and recorded (mutex-guarded) for the
  hint; everything else is unchanged. Existing tests asserting
  `check failed` for other errors must still pass.
- `runChecks` returns the recorded checks alongside the exit code
  (e.g. `(int, []Check)`); update its callers and tests.
- `run` then calls the hint function (design point 3) with the cli
  flags, the recorded checks, M, the logger and a `knownHostsEnv`
  (`realKnownHostsEnv()` in production; injected in tests), after
  `runChecks` returns, so the hint is the last output. Make `run`'s env
  injectable the simplest way that keeps `main` unchanged in spirit
  (e.g. an unexported `runWith(…, env)` that `run` wraps).
- Tests: hint lines and their presence/absence by count (N=0 → nothing;
  N=1 fixable → lines 1-2 only; K and F mixed; first-run rule edges:
  N=2 of 2 → no line 4, N=3 of 6 → line 4, N=3 of 7 → no line 4); the
  echoed command for -c/-s/-S/--connect-default=ssh_config…, quoting a
  config path with a space, `>> file` vs the differing-files wording;
  stdout stays empty. Assert log output text.

## Task 3: README

Files: README.md.

Design point 5. Quote every log message verbatim from the code (grep
it). Match the README's style (setext top-level headings, `###`
subsections, 4-space indented code blocks, British spelling, ~72-col
wrap).
