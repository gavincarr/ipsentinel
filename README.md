
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

`ipsentinel` has two commands. `check` (the default) runs the checks;
`authorized-keys` generates locked-down `authorized_keys` lines for the
monitoring key instead (see [Authorized keys](#authorized-keys)). Since
`check` is the default, the command name can be left off and its flags
given directly, so `ipsentinel -i KEY -c ipsentinel.yml -s example.com`
and `ipsentinel check -i KEY -c ipsentinel.yml -s example.com` are
equivalent.

Only `-c`/`--config` and `-v`/`--verbose` are shared by both commands;
they may go before or after the command name. The remaining flags
(`-i`, `-s`/`--strip`, `-S`/`--strip-all`, `-C`, `-t`, `-r`,
`--retry-delay`) belong to `check`: `ipsentinel check --help` lists
them, and they are rejected with `authorized-keys`.

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
    gitlab.example.com:
      type: connect

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
  - `connect`: for hosts reached through a port forward on another
    machine, so the ip is on the forwarder, not the host (see
    [Connect checks](#connect-checks)). ssh straight to the ip, and pass
    if that succeeds; the `ip address` output is not checked.

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

### Connect checks

Some hosts are reached through a port forward: the ip is configured on
another machine (say a hypervisor) that DNATs a port on it to the host's
private address. The ip then never appears in the host's `ip address`,
and an external echo service sees its egress address instead, so neither
`iproute2` nor `ifconfig` can check it.

A `connect` check runs `ssh -o BatchMode=yes -o HostName=<ip> <host> ...`
instead: the same ssh as the other types, but pointed at the expected ip
itself. It passes if ssh succeeds. Since BatchMode refuses an unknown or
changed host key, success proves the ip — via whatever forward sits in
front of it — still reaches a machine holding the host's known host key.

Only `HostName` is overridden: a command-line `-o` beats `~/.ssh/config`
just for that option, so the port, user, identity and everything else
still come from the host's `~/.ssh/config` entry. E.g. with
`Host gitlab` / `Port 1027` there, a `gitlab,116.202.209.119` check
connects to `116.202.209.119` port 1027.

ipsentinel deliberately won't auto-accept host keys (that would defeat
the check), so each connect host needs a one-off interactive setup to
record its key under the new name, `[<ip>]:<port>` (or just `<ip>` on
port 22). Until that's done — and again whenever a connect host's ip
changes, or a new connect host is added — its check fails with `Host
key verification failed`:

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
both entries.


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
no stripping — so pass the names you'll ssh to. Each host's check type
comes from the `-c` config file:

- a config key equal to the host wins;
- otherwise, the config keys starting with the host plus a dot are
  candidates, so `web1` finds `web1.example.com`. If several match
  (`web1.example.com` and `web1.example.net`), they must all have the
  same check type (or at least the same forced command, as `iproute2`
  and `connect` share), or the host is skipped with an error naming
  them;
- a host matching no key (or with no `-c` at all) uses the default,
  `iproute2`.

An invalid hostname is likewise skipped with an error. The exit code is
1 if any host was skipped, else 0.

    $ ipsentinel -c ipsentinel.yml authorized-keys --from 192.0.2.10 \
        ~/.ssh/id_ipsentinel.pub web1 db.example.com
    web1            from="192.0.2.10",restrict,command="ip address" ssh-ed25519 AAAA... root@monitor
    db.example.com  from="192.0.2.10",restrict,command="ip address; TOKEN=..." ssh-ed25519 AAAA... root@monitor

With **no HOST arguments**, there is one row per check variant instead,
labelled `iproute2`, `connect`, `aws`, `ifconfig`, `ifconfig-v4` and
`ifconfig-v6` (the last two being `ifconfig` with `ip_version` 4 and 6)
— handy for pasting by hand. `-c` is not used in this mode. The
`connect` line is identical to the `iproute2` one, since both run
`ip address`.

`--from PATTERNS` adds an sshd `from=` restriction: a comma-separated
list of the addresses, CIDRs or hostname patterns (with `!` negation)
the key may be used from — normally the monitoring host's address(es).
Without it, a warning is logged on stderr, since the generated lines
then accept the key from any address; the output is still produced and
the exit code unaffected.

Hosts behind a port forward that masquerades (SNATs) the connection —
typically `connect` hosts — see it arrive from the forwarder's address,
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

