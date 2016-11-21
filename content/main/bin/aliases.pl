#!/usr/bin/perl -w

##########################################################################
#
#    Neet: Network discovery, enumeration and security assessment tool
#    Copyright (C) 2008-2016 Jonathan Roach
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

#use strict;

my $file;
if (defined($ARGV[0]) && -f ("$ARGV[0]")){
	$file="$ARGV[0]";
}

exit 1 if (!defined($file));

my $FH;
if (open($FH,"$file")){
	my @live=<$FH>;
	close $FH;
	my $common=0;
	for (my $o=1; $o<4; $o++){
		if (_common(\@live,$o)){
			$common=$o;	
		} else {
			last;
		}
	}
	#print "Found that $common octets were common\n";
	# Create the aliases
	# No point creating them if there's no commonality.
	exit 0 if ($common == 0);
	for my $element (@live){
		next if (length($element)<7);
		next if ($element !~/^\d{1,3}\./);		
		my @octets=split ("\\.", $element);
		for (my $a=0; $a<$common; $a++){
			shift (@octets);
		}
		my $alias=join ".", @octets;
		chomp $alias;
		$alias .= "~$element";
		print $alias;
	}
}

sub _common {
	my $array=shift();
	my $oct=shift();
	my $sample=undef;
	my $common=1;
	for my $element (@{$array}){
		next if (length($element)<7);
		exit 1 if ($element !~/^\d{1,3}\./);		
		my @octets=split "\\.", $element;
		$sample=$octets[$oct-1] if (!defined($sample));
		if ($octets[$oct-1] != $sample){
			$common=0;
			last;
		}
	}
	return $common;
}

