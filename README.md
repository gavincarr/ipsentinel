
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
    ipsentinel authorized-keys [--from PATTERNS] PUBKEY [HOST...]
    ipsentinel known-hosts [flags] < hosts.csv

`ipsentinel` has three commands. `check` (the default) runs the checks;
`authorized-keys` generates locked-down `authorized_keys` lines for the
monitoring key instead (see [Authorized keys](#authorized-keys));
`known-hosts` prints `known_hosts` lines for `connect: ip` hosts (see
[Known hosts](#known-hosts)). Since
`check` is the default, the command name can be left off and its flags
given directly, so `ipsentinel -i KEY -c ipsentinel.yml -s example.com`
and `ipsentinel check -i KEY -c ipsentinel.yml -s example.com` are
equivalent.

Only `-c`/`--config`, `--connect-default` and `-v`/`--verbose` are
shared by all commands; they may go before or after the command name.
The remaining flags (`-i`, `-s`/`--strip`, `-S`/`--strip-all`, `-C`,
`-t`, `-r`, `--retry-delay`) belong to `check`: `ipsentinel check
--help` lists them, and they are rejected with `authorized-keys`.
`known-hosts` also takes `-s` and `-S`, but only after its name.

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
(`web1.example.com` => `web1`). `-s` and `-S` are mutually exclusive.
Run `ipsentinel --help` for the shared options and
`ipsentinel check --help` for the check options.


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

By default every host is checked the same way: ssh to the hostname and
look for the expected ip in `ip address`. Some hosts need something
else — most notably AWS EC2 instances, whose public IP is a 1:1 NAT
mapping held in AWS infrastructure rather than configured on the
instance, so it never appears in `ip address` output. Pass a YAML config
file with `-c`/`--config`, keyed by hostname *as it appears on stdin*
(before any `-s`/`-S` stripping):

    web1.example.com:
      check: aws
    web2.example.com:
      check: ifconfig
    web3.example.com:
      connect: ip           # check defaults to iproute2
    gitlab.example.com:
      connect: ip
      check: none

Each host has two independent settings: **`connect`**, how ssh reaches
the host, and **`check`**, what counts as a pass.

### `connect`

- `ssh_config` (the default): ssh to the hostname, resolved as usual via
  `~/.ssh/config` and DNS. A pass proves the expected ip is configured
  on (or, for `aws`/`ifconfig`, belongs to) the box holding the host's
  key.
- `ip`: ssh straight to the expected ip with `-o HostName=<ip>`. A pass
  proves traffic to the ip reaches the box holding the host's key. See
  [`connect: ip`](#connect-ip) below.

### `check`

| check              | remote command                                       | passes if |
|--------------------|------------------------------------------------------|-----------|
| `iproute2` (default) | `ip address`                                       | the expected ip is in the output |
| `aws`              | `ip address`, plus the instance's public IPv4 from the EC2 Instance Metadata Service | the expected ip is in the output |
| `ifconfig`         | `ip address`, plus the host's public addresses from `https://ifconfig.me` | the expected ip is in the output |
| `none`             | `true`                                               | ssh succeeds |

- `aws` lets both private and public EC2 addresses be verified.
- `ifconfig` is the non-AWS equivalent, for hosts behind a NAT gateway.
  It always asks over both IPv4 and IPv6 (`curl -4`, then `curl -6`)
  and passes if the expected ip is in any of the output, so dual-stack
  hosts, and hosts with both A and AAAA records, just work. A family the
  host lacks is tolerated: that `curl` simply fails (normally at once,
  at worst after its 2s cap).
- `none` reads nothing from the host: the ssh connection itself is the
  check. It therefore **requires `connect: ip`** — with `ssh_config` it
  would pass whenever ssh to the name works, without ever testing the
  ip, so that combination is rejected at startup. Its forced command,
  `true`, also gives the monitoring key the least possible capability on
  the host (see [Authorized keys](#authorized-keys)).

`aws` and `ifconfig` require `curl` and a POSIX login shell on the
target host.

Every check works with either connect mode. In particular,
`connect: ip` with `check: iproute2` proves both things at once — that
the ip reaches the box holding the host key, *and* that the ip is
configured on it — but it needs ssh to answer on that ip itself, so it
doesn't suit hosts behind a port forward (use `check: none` for those).

### Defaults and validation

Hosts absent from the config file, or with no `check`, use `iproute2`.
Hosts absent from the config file, or with no `connect`, use the
`--connect-default` mode, which is `ssh_config` unless you say
otherwise. `--connect-default=ip` is mainly for trying `connect: ip`
across all hosts at once before changing anything per host; an explicit
`connect` in an entry always wins over it. Because it changes which
entries are valid (`check: none` with no `connect` is fine under
`--connect-default=ip`, rejected otherwise), it's a shared flag, so
`check` and `authorized-keys` validate a config identically.

Config entries for hosts not present on stdin are ignored, so one config
file can cover a superset of any given input.

Mistakes are errors at startup, naming the file and host: unknown keys,
unknown `connect` or `check` values, and `check: none` without
`connect: ip`.

### Migrating from `type`

Earlier versions had a single `type` key (`iproute2`, `aws`, `ifconfig`
or `connect`) that mixed up the two settings. It is now rejected with an
error suggesting the replacement:

| old                | new |
|--------------------|-----|
| `type: iproute2`   | `check: iproute2` (or nothing: it's the default) |
| `type: aws`        | `check: aws` |
| `type: ifconfig`   | `check: ifconfig` |
| `type: connect`    | `connect: ip` and `check: none` |

`type: connect` hosts' forced command changes from `ip address` to
`true`, so their `authorized_keys` lines must be regenerated and
redeployed (see [Authorized keys](#authorized-keys)); until then the
old forced command still runs and the check still passes, but the key
keeps more capability than it needs.

The old `ip_version` key, which forced the `ifconfig` check's `curl` to
one family, is likewise rejected: `ifconfig` checks query both families,
so just remove it. (Its forced command has changed too; see
[Authorized keys](#authorized-keys) for regenerating deployed lines.)

### `connect: ip`

Some hosts are reached through a port forward: the ip is configured on
another machine (say a hypervisor) that DNATs a port on it to the host's
private address. The ip then never appears in the host's `ip address`,
and an external echo service sees its egress address instead, so neither
`iproute2` nor `ifconfig` can check it. `connect: ip` with `check: none`
covers these.

`connect: ip` runs `ssh -o BatchMode=yes -o HostName=<ip> <host> ...`:
the same ssh as usual, but pointed at the expected ip itself. Since
BatchMode refuses an unknown or changed host key, success proves the ip
— via whatever forward sits in front of it — still reaches a machine
holding the host's known host key. That proof rests on host keys being
unique to their host: cloned VMs that share host keys would defeat it,
since any of the clones would pass. Give each clone its own keys.

Only `HostName` is overridden: a command-line `-o` beats `~/.ssh/config`
just for that option, so the port, user, identity and everything else
still come from the host's `~/.ssh/config` entry. E.g. with
`Host gitlab` / `Port 1027` there, a `gitlab,116.202.209.119` check
connects to `116.202.209.119` port 1027.

ipsentinel deliberately won't auto-accept host keys (that would defeat
the check), so each `connect: ip` host needs a one-off setup to record
its key under the new name, `[<ip>]:<port>` (or just `<ip>` on port 22).
Until that's done — and again whenever such a host's ip changes, or a
new one is added (including via `--connect-default=ip`) — its check
fails with `Host key verification failed`.

`ipsentinel known-hosts` is the first-line fix: it prints the lines to
add (see [Known hosts](#known-hosts)). For a host it can't handle (it
reports hosts with no known key under the usual name), do the setup by
hand:

1. Get the fingerprint of the host's known-good key, as already
   recorded under its usual name:

       ssh-keygen -l -F '[<host>]:<port>'    # or '<host>' on port 22

2. Connect to the ip interactively:

       ssh -o HostName=<ip> <host> true

   ssh shows the key's fingerprint and asks whether to continue.
   **Compare it against the fingerprint from step 1 before answering
   `yes`**; if they differ, answer no — the ip is reaching some other
   machine.

The host key is then stored in `known_hosts` under two names, the host's
usual one and the ip one, so if the host's key is ever rotated, update
both entries. Re-running `known-hosts` after a rotation won't replace
the stale ip entry: it reports a foreign key on the ip instead.


Known hosts
-----------

A `connect: ip` check looks the server's key up under the ip name, so
until the ip has an entry in `known_hosts` it fails every host.
`ipsentinel known-hosts` prints the missing entries: for each
`connect: ip` host on stdin, it copies the key(s) already trusted for
the host under its usual name to the ip name (`[<ip>]:<port>`, or just
`<ip>` on port 22).

It runs `ssh -G` and `ssh-keygen -F` to find the names and keys, and
**connects to nothing**. That is safe because a `known_hosts` line holds
only a public key: it records that this ip must prove it holds the
host's private key, and the next `check` run's handshake does the
proving. If the ip reaches some other machine, `check` fails.

Hosts are read from stdin like `check` does, and `-c`, `--connect-default`
and `-s`/`-S` work the same way (`-i` isn't taken). Only `connect: ip`
hosts are considered. Output on stdout is `known_hosts` lines only;
messages go to stderr. Review the lines, then append them:

    $ tinydnsip -d example.com data |
        ipsentinel known-hosts -c ipsentinel.yml -s example.com --connect-default ip
    [192.0.2.10]:2222 ssh-ed25519 AAAA...
    $ tinydnsip -d example.com data |
        ipsentinel known-hosts -c ipsentinel.yml -s example.com --connect-default ip >> ~/.ssh/known_hosts

Things to know:

- **Hashing follows `HashKnownHosts`.** If ssh would hash names for the
  host, so do the printed lines.
- **Re-runs are idempotent.** A key already recorded under the ip name
  isn't printed again, so a second run prints nothing new.
- **Hosts with a `HostKeyAlias`** need nothing: ssh already looks the ip
  up under the alias, and they are skipped.
- **The exit code is 1 if any host has a problem**, and nothing is
  printed for that host. Each problem is logged:
  - `no known host key for host; add it by hand, see README`: no key
    is recorded under the host's usual name, so there is nothing to
    copy. Use the manual steps under [`connect: ip`](#connect-ip).
  - `ip already has a different host key; not adding`: the ip name
    already holds a key that isn't one of the host's. Investigate
    before doing anything else (the ip may reach a different machine,
    or the host's key may have rotated); don't override it blindly.
  - Others: `ssh -G failed` for the host, or an unreadable
    `known_hosts` file (`looking up host key failed`), which is reported
    rather than skipped so it can't hide a key.


Authorized keys
---------------

The monitoring key only ever needs to run one command on each host, so
it can be locked down on the targets with an `authorized_keys` forced
command. `ipsentinel authorized-keys PUBKEY [HOST...]` generates those
lines from the same source of truth ipsentinel uses for its checks, so
each host's line forces exactly the command ipsentinel sends it.

The `authorized-keys` command runs **no checks and never reads stdin**:
the hosts are given as arguments. `PUBKEY` is an OpenSSH public key file
(e.g. `/root/.ssh/id_ipsentinel.pub` — the `.pub`, not the private key).
Output is a two-column table on stdout — a label, then the
`authorized_keys` line, with the labels padded with spaces so the lines
line up (no tabs, no header):

    <label>  [from="...",]restrict,command="<check command>" <public key>

With **HOST arguments**, there is one row per host, in the order given
(repeats are printed once). Each label is the host exactly as given —
no stripping — so pass the names you'll ssh to. Each host's forced
command comes from its `check` in the `-c` config file (`connect`
doesn't affect it: it only changes the ssh options on the monitoring
side):

- a config key equal to the host wins;
- otherwise, the config keys starting with the host plus a dot are
  candidates, so `web1` finds `web1.example.com`. If several match
  (`web1.example.com` and `web1.example.net`), they must all have the
  same check (their `connect` may differ), or the host is skipped with
  an error naming them and their checks;
- a host matching no key (or with no `-c` at all) uses the default
  check, `iproute2`.

An invalid hostname is likewise skipped with an error. The exit code is
1 if any host was skipped, else 0.

    $ ipsentinel -c ipsentinel.yml authorized-keys --from 192.0.2.10 \
        ~/.ssh/id_ipsentinel.pub web1 db.example.com
    web1            from="192.0.2.10",restrict,command="ip address" ssh-ed25519 AAAA... root@monitor
    db.example.com  from="192.0.2.10",restrict,command="ip address; TOKEN=..." ssh-ed25519 AAAA... root@monitor

With **no HOST arguments**, there is one row per check instead,
labelled `iproute2`, `aws`, `ifconfig` and `none`, handy for pasting by
hand. (Earlier versions also printed `ifconfig-v4` and `ifconfig-v6`,
and a `connect` row identical to `iproute2`'s; every `ifconfig` host now
shares the one line, and `check: none` hosts use the `none` line.) `-c`
is not used in this mode.

`--from PATTERNS` adds an sshd `from=` restriction: a comma-separated
list of the addresses, CIDRs or hostname patterns (with `!` negation)
the key may be used from — normally the monitoring host's address(es).
If `--from` isn't given, the `IPSENTINEL_FROM` environment variable is
used instead, so the usual list can be set once — exported in your
shell, or in a `.env`/`.env.local` file in the directory you run
ipsentinel from (both are loaded at startup):

    IPSENTINEL_FROM=104.237.141.63,192.168.188.199,100.66.118.30

An explicit `--from` always overrides it (e.g. for hosts behind a
forward, below). With neither, a warning is logged on stderr, since the generated lines
then accept the key from any address; the output is still produced and
the exit code unaffected.

Hosts behind a port forward that masquerades (SNATs) the connection —
typically `connect: ip` hosts — see it arrive from the forwarder's address,
not the monitoring host's, so their `from=` must be that address.
Generate their lines separately, e.g.
`ipsentinel -c ipsentinel.yml authorized-keys --from <forwarder internal ip> ~/.ssh/id_ipsentinel.pub gitlab`.

To deploy, pipe each line to its host over ssh's stdin (which needs no
quoting, unlike embedding the line — which contains double quotes and
`$` — in a remote command string). Because each `ssh` reads from its own
`printf` pipe, it can't swallow the rest of the loop's input. The
deploying ssh must of course use a key other than the one being locked
down:

    ipsentinel -c ipsentinel.yml authorized-keys --from 192.0.2.10 ~/.ssh/id_ipsentinel.pub host1 host2 |
      while read -r host line; do
        printf '%s\n' "$line" | ssh "$host" 'umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
      done

`read -r` with the default `IFS` puts the label in `host` and the rest
of the row, with the padding stripped but otherwise byte-for-byte, in
`line`.

Things to know:

- **It appends.** sshd uses the *first* line in `authorized_keys` that
  matches a key, so remove any older line for the same key first (an
  earlier unrestricted line would silently win; an earlier forced line
  would force a stale command).
- **`restrict` needs OpenSSH 7.2 or later on the target.** Older sshd
  doesn't recognise it and ignores the whole line, so the key simply
  stops working there.
- **Regenerate and redeploy** whenever a host's `check` changes, or when
  an ipsentinel upgrade changes its check commands: the forced command
  wins over whatever ipsentinel asks for, so a stale line keeps running
  the old command. In particular, `ifconfig` lines deployed before it
  started querying both IPv4 and IPv6 (including any from `ip_version`),
  and lines for former `type: connect` hosts (now `check: none`, forced
  command `true`), must be regenerated. Changing only a host's `connect`
  needs no redeploy.
- **One key, one job.** Once locked down, the key can only run the check
  command on that host, so anything else using it from the monitoring
  host (rsync, backups, ad-hoc ssh) needs its own key.


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

