## What is it

This script checks bunch of domains for certificate expiration date.

It forks up to 10 subproccesses at once to check certificates in parallel
so it is slightly faster than simple bash wrapper around openssl.

Mind that common number of processing is quite big because
every perl subprocess starts openssl subprocesses.

### Usage

./async_tls_check.pl <path to file with domains list>

Requires Perl and openssl uitility.

Dafault port - 443.

Default file with domains - domains_example.txt.

Output format:

expiration date \t domain (name)


### TODO

Maybe do not check domains which are not expired soon.

Get info from previous run.
