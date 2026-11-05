
Overview
--------

`ipsentinel` is a system that takes a set of `hostname,ip` pairs on
stdin and does an `ssh hostname ip address` on each one (supporting
`~/.ssh/config`), and then confirms that the ip is (still) present
in that output. On any error (eg ssh errors OR if ip is not found)
it reports an error.


Installation
------------

    go install github.com/gavincarr/ipsentinel@latest


Usage
-----

    ipsentinel [check] [flags] < hosts.csv
    ipsentinel authorized-keys [flags] PUBKEY < hosts.csv

`ipsentinel` has two commands. `check` (the default) runs the checks;
`authorized-keys` generates locked-down `authorized_keys` lines for the
monitoring key instead (see [Authorized keys](#authorized-keys)). Since
`check` is the default, the command name can be left off and its flags
given directly, so `ipsentinel -i KEY -c ipsentinel.yml -s example.com`
and `ipsentinel check -i KEY -c ipsentinel.yml -s example.com` are
equivalent.

The `-c`/`--config`, `-s`/`--strip`, `-S`/`--strip-all` and
`-v`/`--verbose` flags are shared by both commands, so they resolve
check types and ssh targets identically; they may go before or after
the command name. The remaining flags (`-i`, `-C`, `-t`, `-r`,
`--retry-delay`) belong to `check`: `ipsentinel check --help` lists
them.

`ipsentinel` reads `hostname,ip` pairs on stdin, one per line. Blank
lines and lines beginning with `#` are ignored. Both IPv4 and IPv6
addresses are supported (each ip is validated and canonicalised, so
`FE80::1` and `fe80::1` are treated identically):

    $ ipsentinel <<'EOF'
    # hostname,ip
    web1.example.com,10.0.0.1
    web2.example.com,fe80::1
    EOF

By default the hostname is used verbatim as the ssh target. To drive
ssh via short `~/.ssh/config` aliases, strip a domain suffix with
`-s`/`--strip` (a leading dot is added if absent, so `web1.example.com`
becomes `web1`):

    $ ipsentinel -s example.com < hosts.csv

Or reduce every hostname to its leftmost label with `-S`/`--strip-all`
(`web1.example.com` => `web1`). Run `ipsentinel --help` for the shared
options and `ipsentinel check --help` for the check options.


Output
------

A clean run prints nothing and exits 0, so `ipsentinel` can be run from
cron without a filter — you only hear from it when something is wrong.
On stderr you get alerts for failed checks, a warning for malformed
input lines, and a summary line when the run ends with failures; the
exit code is 1 if any check failed.

`-v`/`--verbose` is repeatable and raises the verbosity a level each
time:

- (none) — warnings and alerts only.
- `-v` — adds the run summary: how many checks were parsed, and how
  many passed at the end.
- `-vv` — adds per-check detail: a line for every successful check and
  for every retry pass.

Note that a transient failure that recovers on a retry is a success,
and so is reported only at `-vv`.

Log output is colourised only when stderr is a terminal, so cron mail
and redirected output stay plain. Two environment variables override the
detection: `NO_COLOR` (any value) forces colour off
([no-color.org](https://no-color.org)), and `FORCE_COLOR` (any value)
forces it on — useful when piping to a pager, e.g.
`ipsentinel ... 2>&1 | less -R`. `FORCE_COLOR` wins if both are set.


Retries
-------

Not every ssh failure means a host has genuinely lost its IP. Transient
failures — an early handshake abort (`kex_exchange_identification: Connection
closed by remote host`), a connection reset, or a per-check timeout — are
collected and retried before they alert. Hard failures — authentication
(`Permission denied`), host-key mismatch, DNS resolution, or a wrong/missing
IP — are definitive and alert immediately.

Soft failures are retried up to `--retries` times (default 2) with
exponential backoff: pass N waits `--retry-delay * 2^(N-1)` (default base
`5s`, so 5s then 10s). A soft failure alerts only if it still fails after
the last pass; one that recovers on a retry is a success. Set `--retries 0`
to disable retries and alert every failure immediately.

Note that the delay compounds: the worst-case added wall-clock for a run is
`--retry-delay * (2^--retries - 1)` (15s at the defaults), so raising
`--retries` well above the default lengthens a failing run substantially.

- `-r, --retries` — number of retry passes for transient failures (default 2).
- `--retry-delay` — base backoff before the first retry pass (default 5s).


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
      type: ifconfig
    web3.example.com:
      type: iproute2
    web4.example.com:
      type: ifconfig
      ip_version: "6"

Supported per-host keys:

- `type`: the check type — one of:
  - `iproute2` (the default): run `ip address` and look for the
    expected ip.
  - `aws`: additionally query the EC2 Instance Metadata Service for the
    instance's public IPv4, so both private and public addresses can be
    verified.
  - `ifconfig`: the non-AWS equivalent — additionally query
    `https://ifconfig.me` for the host's public IPv4 as seen from the
    outside, for hosts behind a NAT gateway.

  `aws` and `ifconfig` require `curl` and a POSIX login shell on the
  target host.

- `ip_version`: `"4"` or `"6"` — forces the `ifconfig` check's `curl` to
  that address family (via `curl -4`/`curl -6`). Use it on dual-stack
  hosts where `ifconfig.me` would otherwise return the family you're not
  tracking. Only valid with `type: ifconfig`; omit it to let `curl`
  choose.

Hosts absent from the config file (or with no `type`) use `iproute2`.
Config entries for hosts not present on stdin are ignored, so one
config file can cover a superset of any given input.


Authorized keys
---------------

The monitoring key only ever needs to run one command on each host, so
it can be locked down on the targets with an `authorized_keys` forced
command. `ipsentinel authorized-keys PUBKEY` generates those lines from
the same source of truth ipsentinel uses for its checks, so each host's
line forces exactly the command ipsentinel sends it.

The `authorized-keys` command runs **no checks**. It reads stdin
exactly as normal (same `-c`, `-s`/`-S` handling, same alerts for
malformed lines) and prints one tab-separated line per distinct ssh
target to stdout, in input order:

    <target><TAB>[from="...",]restrict,command="<check command>" <public key>

`PUBKEY` is an OpenSSH public key file (e.g. `/root/.ssh/id_ipsentinel.pub`
— the `.pub`, not the private key). The target is the hostname after any
`-s`/`-S` stripping, i.e. what ssh is given. Hosts that appear more than
once (as tinydns A and AAAA records often do) get a single line. If two
input names strip to the same target but have different check types,
that target is omitted with an error rather than guessed at. The exit
code is 1 if any target was omitted or any input line was malformed.

`--from PATTERNS` adds an sshd `from=` restriction: a comma-separated
list of the addresses, CIDRs or hostname patterns (with `!` negation)
the key may be used from — normally the monitoring host's address(es).

    $ ipsentinel -c ipsentinel.yml -s example.com \
        authorized-keys --from 192.0.2.10 ~/.ssh/id_ipsentinel.pub < hosts.csv
    web1	from="192.0.2.10",restrict,command="ip address" ssh-ed25519 AAAA... root@monitor

To deploy, pipe each line to its host over ssh's stdin (which needs no
quoting, unlike embedding the line — which contains double quotes and
`$` — in a remote command string). The deploying ssh must of course use
a key other than the one being locked down:

    ipsentinel -c ipsentinel.yml -s example.com authorized-keys --from 192.0.2.10 ~/.ssh/id_ipsentinel.pub < hosts.csv |
      while IFS="$(printf '\t')" read -r host line; do
        printf '%s\n' "$line" | ssh "$host" 'umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
      done

Things to know:

- **It appends.** sshd uses the *first* line in `authorized_keys` that
  matches a key, so remove any older line for the same key first (an
  earlier unrestricted line would silently win; an earlier forced line
  would force a stale command).
- **`restrict` needs OpenSSH 7.2 or later on the target.** Older sshd
  doesn't recognise it and ignores the whole line, so the key simply
  stops working there.
- **Regenerate and redeploy** whenever a host's `type` or `ip_version`
  changes, or when an ipsentinel upgrade changes its check commands:
  the forced command wins over whatever ipsentinel asks for, so a stale
  line keeps running the old command.
- **One key, one job.** Once locked down, the key can only run the check
  command on that host, so anything else using it from the monitoring
  host (rsync, backups, ad-hoc ssh) needs its own key.


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

