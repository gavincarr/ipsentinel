
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


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

