# known-hosts subcommand — implementation plan

Spec: none written; the design was agreed in chat (2026-11-05) and is
restated in full under "Design" below. Treat "Design" as the spec.

## Why

Running ipsentinel with `--connect-default ip` (or `connect: ip` in the
config) for the first time fails every such host with
`Host key verification failed`: with `-o HostName=<ip>` and no
`HostKeyAlias`, ssh looks the host key up under the ip name
(`[<ip>]:<port>`, or plain `<ip>` on port 22), not under the host's usual
name, so even hosts whose key is long known are "unknown". The README's
manual fix (fingerprint compare + interactive ssh) is per host; with 40
hosts that's impractical. The user wants a generator.

## Design

A new subcommand, `ipsentinel known-hosts`, used exactly like `check` on
the same stdin:

    tinydnsip -d profound.net data | \
      ipsentinel known-hosts -c ipsentinel.yml -s profound.net --connect-default ip \
      >> ~/.ssh/known_hosts

- **Connects to nothing.** For every connect=ip host it finds the host
  key(s) already trusted for the host under its usual known_hosts name,
  and prints the same key(s) under the ip name. This is safe without a
  scan: a known_hosts line carries only a public key, so it just records
  "this ip must prove it holds this host's private key", and the next
  `check` run's ssh handshake is what verifies it. No ssh-keyscan, no
  option for one.
- **Prints lines to stdout only**; the user reviews and appends them
  themselves. It never writes known_hosts. stdout carries nothing but
  known_hosts lines, so `>> known_hosts` is always safe.
- **Problems go to stderr** (slog), one per host, and make the exit code 1:
  - the host has no known key under its usual name (it needs the README's
    manual steps);
  - the ip name already has a key that is not one of the host's keys
    (red flag: the ip may reach another machine) — nothing is printed for
    that host;
  - `ssh -G` fails for the host.
- **Idempotent:** keys already recorded under the ip name are not printed
  again, so re-running prints nothing new. A host already fully recorded is
  silent (Debug only).
- **Hashing:** when the effective ssh config has `HashKnownHosts yes`
  (Ubuntu's default), the ip name is hashed (`|1|salt|hash`), matching the
  file's style; otherwise it's written plain.
- **Resolution mirrors ssh exactly**, via `ssh -G`, so `~/.ssh/config`
  aliases, `Port`, `HostKeyAlias` and the known_hosts file list all resolve
  as they do for `check`.
- Hosts that are not connect=ip are skipped (Debug log). Out of scope:
  editing known_hosts, prompting, key rotation, connect=ssh_config hosts.

## Global Constraints

- Go, existing module; **no new dependencies** (HMAC-SHA1 hashing via the
  stdlib `crypto/hmac` + `crypto/sha1`; do not add golang.org/x/crypto).
- Logging via the existing `*slog.Logger` only; never the stdlib `log`
  package.
- Shell out to the real `ssh` and `ssh-keygen` binaries (the project's
  philosophy: honour `~/.ssh/config` by using real ssh). Pass `--` before
  any hostname argument to `ssh`; hostnames reaching this code have
  already passed `validHostname` in `parseInput`.
- stdout is the data channel: only known_hosts lines ever go there. All
  diagnostics go to the logger (stderr).
- Match the existing code's style: thorough doc comments explaining *why*,
  table-driven tests, `gofmt`, `go vet ./...` and `go test ./...` clean.
- Commits: Conventional Commits, e.g. `feat(known-hosts): ...`, body
  explaining why, ending with the trailer block
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Commit only; never push.
- kong: explicit `name=` on every field; test the grammar via `kong.New` +
  `Parse` (see the existing `TestCLIGrammar` in authkeys_test.go), and
  assert stdout and stderr separately in any CLI-level test.

## Task 1: known-hosts command, code and tests

Files: create `knownhosts.go`, `knownhosts_test.go`; modify `main.go`
(CLI struct, command dispatch, check-flag rejection), and extend
`TestCLIGrammar` (authkeys_test.go) or add a sibling grammar test.

### CLI

Add to `CLI`, after `AuthorizedKeys`:

    KnownHosts KnownHostsCmd `kong:"cmd,name='known-hosts',help='Run no checks and connect to nothing. Instead, for each connect: ip hostname,ip pair on stdin, print known_hosts lines recording the host key already trusted for the host under its ip name ([ip]:port, or ip on port 22), ready to append to known_hosts. See README.'"`

`KnownHostsCmd` has its own `Strip` (`name='strip',short='s',xor='strip'`)
and `StripAll` (`name='strip-all',short='S',xor='strip'`) fields with the
same help text as `CheckCmd`'s, so the user's existing `-s profound.net`
works after the command name. Verify with grammar tests that
`known-hosts -s example.com` and `known-hosts -S` parse into
`KnownHosts`, that `known-hosts -s x -S` is rejected (xor), and that
`check -s x` / bare `-s x` still parse into `Check` as before.

Generalise `AuthorizedKeysCmd.AfterApply`'s "check flags given before
the command name" rejection into a helper shared by both commands (so
`ipsentinel -s x known-hosts` errors with
`--strip is a check flag and cannot be used with known-hosts`, and the
authorized-keys error message is unchanged). Grammar-test both.

In `main`, dispatch `"known-hosts"` to
`runKnownHosts(os.Stdin, cli.KnownHosts.StripAll, cli.KnownHosts.Strip, config, log, os.Stdout, realKnownHostsEnv())`
(names are suggestions; keep the shape: reader in, writer out, injected
environment, exit code returned).

### Behaviour of runKnownHosts

1. `parseInput(r, LogAlerter{log}, stripAll, domain, config)` — reuse it
   unchanged; parse failures count as problems.
2. For each check with `Connect != connectIP`: Debug log, skip.
3. For each connect=ip check, resolve ssh settings twice via `ssh -G`:
   - **ip side**: `ssh -G -o HostName=<ip> -- <hostname>` — exactly what
     `check` effectively runs, so `Match` blocks see the same thing. From
     it take `port`, `hostkeyalias`, `userknownhostsfile`,
     `globalknownhostsfile`, `hashknownhosts`.
   - **host side**: `ssh -G -- <hostname>` — take `hostname` and `port`.
   `ssh -G` prints one `key value` per line, keys lowercase; the two
   `*knownhostsfile` values are space-separated absolute paths (ssh
   expands `~`); `hostkeyalias` is absent when unset. Real output seen on
   the dev box (OpenSSH 9.6):

       hostname somealias
       port 22
       hashknownhosts yes
       globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2
       userknownhostsfile /home/gavin/.ssh/known_hosts /home/gavin/.ssh/known_hosts2

   Treat a `hostkeyalias` value of `none` as unset. A non-zero exit from
   `ssh -G` is a per-host problem (log the trimmed stderr). Bound each
   subprocess with a timeout (e.g. 10s via `exec.CommandContext`).
4. If `hostkeyalias` is set on the ip side, ssh already verifies ip
   connections against the alias's entry: Debug log, skip, not a problem.
5. Names: `knownHostsName(h, port)` = `h` when port is `22`, else
   `[h]:port` (IPv6 too: `[2001:db8::1]:2222`, plain `2001:db8::1` on 22).
   host name = `knownHostsName(hostSide.hostname, hostSide.port)`;
   ip name = `knownHostsName(c.IP, ipSide.port)`.
6. Files to search: ip side's user files then global files, skipping any
   that don't exist (`ssh-keygen -F` exits 255 "Cannot stat" on a missing
   file).
7. Look keys up with `ssh-keygen -F <name> -f <file>` per file. Exit 0 =
   found, exit 1 = not found (no output), anything else = error (problem
   for this host). Output format (verified):

       # Host [web1]:2222 found: line 1 
       [web1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdRyLKhHVwD0Y6gRBmlREWSPrvWZtpbeHmUkoDrgS+T

   and for a hashed file the host field is `|1|...|...` instead. Skip `#`
   lines and blanks. A line whose first field starts with `@` is a marked
   line: skip `@revoked` and `@cert-authority` lines entirely (never copy
   them). Otherwise field 2 is the key type and field 3 the base64 key;
   ignore any trailing comment. Dedupe keys (type+key).
8. Host keys empty → Error log (`no known host key for host; add it by hand, see README`,
   with hostname, ip and the host name looked up), problem, next host.
9. Ip keys: any ip key not among the host keys → Error log (`ip already has a different host key; not adding`,
   with hostname, ip, ip name), problem, print nothing for this host.
10. Print each host key not already among the ip keys, one line each:
    `<name> <type> <key>`, no comment (a comment would leak the hostname
    into a hashed file). `<name>` is the ip name, hashed when ip side's
    `hashknownhosts` is `yes`.
11. Within one run, keys printed for an ip name count as that ip name's
    keys for later input lines (so a duplicate input line prints nothing
    more, and a second host claiming the same ip name with a different
    key is reported as in step 9). Key the bookkeeping on the plain ip
    name, never the hashed form.
12. Finish: Info log with the number of lines printed; if any problems,
    Warn summary and return 1, else 0.

### Hashing

`|1|` + base64(salt) + `|` + base64(HMAC-SHA1(key=salt, msg=name)), with a
fresh 20-byte `crypto/rand` salt per line (as ssh does). Make the salt
source injectable for tests. Test vector produced by `ssh-keygen -H` on
the dev box: name `[web1]:2222`, salt `uF0fbbkt4hMtByt2CtWcDVjP1OM=` →
`|1|uF0fbbkt4hMtByt2CtWcDVjP1OM=|RIULQ3InVILmUm+hH+P62bLOgF4=`.

### Tests (minimum)

- Parsers: `ssh -G` output parsing; `ssh-keygen -F` output parsing
  (plain, hashed, `@revoked`, `@cert-authority`, comments, trailing
  comment on a key line).
- `knownHostsName`: port 22, other port, IPv6 both ways.
- Hash: the vector above.
- `runKnownHosts` table tests with a fake ssh-settings function and
  **real `ssh-keygen`** over temp known_hosts files (skip the test if
  `ssh-keygen` is not on PATH; generate keys with
  `ssh-keygen -q -t ed25519 -N '' -f ...` or use fixed literal public
  keys). Cases: happy path port 22 and non-22; hashed host entry in the
  file; HashKnownHosts yes output is found by `ssh-keygen -F <ipname>`
  (round-trip); already recorded → no output, exit 0; partial (host has
  ed25519 + rsa, ip has ed25519) → prints only rsa; ip has a foreign key
  → no output, exit 1; host unknown → exit 1; hostkeyalias set → skipped;
  connect=ssh_config host skipped; duplicate input line printed once;
  missing known_hosts file tolerated. Assert stdout and the log output
  separately.
- Grammar tests listed under CLI.

## Task 2: README

Files: `README.md`.

- Add a `Known hosts` section (same heading style as `Authorized keys`,
  placed just before it) documenting `ipsentinel known-hosts`: what it
  does and why it's safe without connecting (the ip must still prove it
  holds the host's private key at the next check), the example pipeline
  from "Design" above with `>> ~/.ssh/known_hosts`, review-before-append,
  hashing follows HashKnownHosts, idempotent re-runs, the two per-host
  problems and what to do about each (no known key → the manual steps;
  foreign key on the ip → investigate, do not override), HostKeyAlias
  hosts need nothing, exit code 1 on any problem.
- In `### connect: ip`, rewrite the one-off setup paragraph so
  `ipsentinel known-hosts` is the first-line fix, keeping the existing
  numbered manual steps as the fallback for hosts it can't handle
  (no known key under the usual name). Keep the "stored under two names /
  rotate both" note, and mention that re-running known-hosts after a key
  rotation won't replace the stale ip entry (it reports a foreign key).
- If the Usage section lists commands, add known-hosts there.
