#!/usr/bin/perl

# Script checks given tls certificates expiration date
# See
# http://www.stonehenge.com/merlyn/UnixReview/col41.html
# https://www.perl.com/article/fork-yeah-/

use strict;
use warnings;

$SIG{INT} = $SIG{TERM} = sub { exit };

my $domains_file = shift || "domains_example.txt";

my $port = 443;
my %domains; # storing domains as keys and insts as values

my %pid_to_host; # storing pids for each checking domains

my $max_children = 10;
my $warnings = 0; # enable to see children's pids

# Main sub for children
# @_[0] = domain url
# @_[1] = common name
sub check_TLS {
    my $dom = shift;
    my $name = shift || "";
    my $expire = `echo | openssl s_client -servername $dom -connect $dom:$port 2>/dev/null | openssl x509 -noout -enddate 2>&1 | cut -d= -f2`;
    if ($expire =~ "^unable") {
	die "Could not get date from $dom ($name)\n"
    };
    chomp (my $enddate = `date -d "$expire" --iso-8601`);
    print "$enddate\t $dom ($name)\n";
}

sub wait_for_a_kid {
    my $pid = wait;
    return 0 if $pid < 0; # wait returns -1 if no child processes
    my $host = delete $pid_to_host{$pid} # delete returns value of deleted k/v
    or warn("Why did I see $pid ($?)\n"), next;
#    warn "reaping $pid for $host\n" if $warnings;
}

open (my $F, "<", $domains_file) || die "Can't open $domains_file: $!\n";

# Getting domains hash
while (<$F>) {
    chomp;
    our ($domain, $name);
    if (/^$/ or /^#/) {next}; # skip comments and blank lines
    ($domain, $name) = split(/#/, $_);
    $domain =~ s/^\s+|\s+$//; # trim whitespaces
    $name =~ s/^\s+|\s+$// unless !defined $name; # trim whitespaces
    $domains{$domain} = $name;
}
close $F;

# Do forking
foreach my $domain (keys %domains) {

    wait_for_a_kid() if keys %pid_to_host > $max_children;
    if (my $pid = fork) { # fork returns 0 for child and !0 for parent
        ## parent does...
        $pid_to_host{$pid} = $domain;
        warn "$pid is processing $domain\n" if $warnings;
    } else {
        ## child does...
	check_TLS($domain, $domains{$domain});
	exit;
    }
}

# Final reap
1 while wait_for_a_kid();
