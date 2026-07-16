
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


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

