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

# Script runs through the neet directories and pulls out a cross-reference of hostnames vs IP addresses. Hosts with multiple IP addresses 

use strict;
use File::Find;

my %reference;

find (\&processFile, ".");

for my $host (keys(%reference)){
	my $addresses;
	for my $ip (@{$reference{$host}}){
		$addresses .= "$ip, ";
	}
	$addresses =~ s/,\s$//;
	print "$host:\t$addresses\n";
}





# --------------------------------------------------------------

sub processFile {
	return 0 if ("$_" ne "hostnames.txt");
	my $path=$File::Find::name;
	$path =~ s/^./$ENV{'PWD'}/;
	#print "Path: $path\n";
	#print "Dir: $File::Find::dir ";
	#print "File: $_\n";

	if (open(F,$path)){
		my @file = <F>;
		for my $line (@file){
			chomp $line;
			my ($IP,$name) = split (" ", $line, 2);
			#print "$IP : $name\n";
			if (!hostHasIp($name,$IP)){
				push @{$reference{$name}}, $IP;
			}
		}
		close F;
	} else {
		print STDERR "Couldn't open $File::Find::name\n";
		return 1;
	}
}

sub hostHasIp {

	my $host=shift();
	my $ip=shift();
	if (exists($reference{$host})){
		for my $addr (@{$reference{$host}}){
			if ("$ip" eq "$addr"){
				return 1;
			}
		}
	} 	
	return 0;
}



