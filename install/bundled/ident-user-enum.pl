#!/usr/bin/env perl
use strict;
use warnings;
use Net::Ident;
use IO::Socket::INET;

my $VERSION = "1.0";
my $usage = "ident-user-enum v$VERSION ( http://pentestmonkey.net/tools/ident-user-enum )

Usage: ident-user-enum.pl ip port [ port [ port ... ] ]

Queries the ident service (113/TCP) to determine the OS-level user running 
the process listening on a given TCP port.  More than one port can be supplied.\n\n";
my $ip = shift or die $usage;
my $port = shift or die $usage;
unshift @ARGV, $port;
my $timeout = 5;

print "ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )\n\n";

while ($port = shift) {
	my $sock = IO::Socket::INET->new(
                                 PeerAddr => $ip,
                                 PeerPort => $port,
                                 Proto    => 'tcp'
				 );

	my $username = Net::Ident::lookup($sock, $timeout);

	if (defined($username)) {
		print "$ip:$port\t$username\n";
	} else {
		print "$ip:$port\t<unknown>\n";
	}
}
