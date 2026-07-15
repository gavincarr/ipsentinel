
Overview
--------

`ipsentinel` is a system that takes a set of `hostname,ip` pairs on
stdin and does an `ssh hostname ip address` on each one (supporting
`~/.ssh/config`), and then confirming that ip is still present in
that output. On any error (eg ssh errors OR if the ip is not found)
it posts an alert somewhere for attention.


Author
------

Gavin Carr <gavin@openfusion.net>


Licence
--------

`ipsentinel` is available under the terms of the MIT Licence.

