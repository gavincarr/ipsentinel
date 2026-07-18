
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
(`web1.example.com` => `web1`). Run `ipsentinel --help` for the full
list of options.


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

Hosts absent from the config file (or with no `type`) use `iproute2`.
Config entries for hosts not present on stdin are ignored, so one
config file can cover a superset of any given input.


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

