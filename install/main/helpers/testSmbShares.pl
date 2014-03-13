#!/usr/bin/perl -w
##########################################################################
#
#    Neet: Network discovery, enumeration and security assessment tool
#    Copyright (C) 2008-2014 Jonathan Roach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Contact: jonnyhightower [at] funkygeek.com
#
##########################################################################

use strict;

# This script should accept the output of shares() in the neet shell
my @data=<STDIN>;
my $ip;

for my $line (@data){
	next if ($line !~ /\S/);
	if ($line =~ /Shares on: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} /){
		$ip=$line; $ip=~s/^[\S\s]+Shares on: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s\S]+/$1/;
		next;
	}
	chomp $line;
	my $share=$line; $share =~ s/^([\S\s]+) Disk [\S\s]+$/$1/;
	my $desc=$line; $desc =~ s/^[\S\s]+ Disk\s+([\S\s]+)$/$1/;
	$share =~ s/\s+$//;
	my $command="smbclient -N //$ip/\"$share\" >/dev/null 2>&1";
	my $rc=system($command);
	$rc=$rc>>8;
	if ($rc == 0){
		print "ANONYMOUS: $ip \"$share\"\n";
	} else {
		print "Authenticated: $ip \"$share\"\n";
	}

}


