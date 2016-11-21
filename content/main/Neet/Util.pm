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

# Util.pm

# Miscellaneous functions for Neet
# Jonathan Roach
# April 2006
# Version

# User input
sub OLDGetKey {
	# Nasty hack to work with ubuntu (Jan 2007)
	my $key=`/bin/bash -c 'read -sn1 result 2>/dev/null && echo \$result'`;
	chomp $key;
	return $key;
}

sub GetKey {
	ReadMode 3;
	my $key = ReadKey 0;
	ReadMode 0;
	return $key;
}

sub GetLine {
	my $line;
	until ($line && $line =~ /\S/){
		$line=<STDIN>;
	}
	return $line;
}

sub GetLineNWS {
	my $line=GetLine();
	$line =~ s/\n//g;
	$line =~ s/\s/_/g;
	return $line;
}

sub PageSeparator {
	print "\n" . "-" x 80 . "\n" . "-" x 80 . "\n\n";
	return 1;
}

sub Stamp {
	my $stamp=`date`;
	chomp $stamp;
	return $stamp;
}

sub Mid {
	my $line=shift();
	$line =~ s/\n$//;
  my ($width,@junk)=GetTerminalSize();
	$width=80 if (!$width);
	if (length($line)<($width-3)){
		$line = " $line ";
		if (length($line) % 2 > 0){
			$line .= " ";
		}
		my $padsize=($width-length($line))/2;
		$line = "-" x $padsize . $line . "-" x $padsize . "\n";
		return $line;
	} else {
		return $line;
	}
}


#************************************************
# Port and Address specification validation
#************************************************
sub IsPortSpec {
	my $spec=shift();
	return 1 if ($spec =~ /^\d+[-,]??\d+$/);
	return 0;
}

sub IsIPSpec {
	my $spec=shift();
	my $status=1;
	if (!defined($spec)){
		return $status;
	}
	if ($spec !~ /\//){
		# Absolute range
		my @octets=split "\\.", $spec;
		return 0 if ($#octets != 3);
		for my $octet (@octets){
			my ($a,$b)=split("-",$octet);
			if ($b){
				$status=0 if ($b !~ /^\d{1,3}$/);
				$status=0 if (($b > 255) || ($b <= $a));
			} else {
				$status=0 if ($octet =~ /-/);
			}
			if ("$a" ne "*"){
				$status=0 if ($a !~ /^\d{1,3}$/);
				$status=0 if ($status && (($a < 0) || ($a > 255)));
			}
		}
	} else {
		# CIDR notation
		my ($net,$mask)=split "/", $spec;
		$status=IsIPSpec($net);
		if ($status){
			if (!IsIPSpec($mask)){
				if (!(($mask =~ /^\d+$/) && ($mask > 0) && ($mask < 33))){
					$status=0;
				}
			}
		}
	}
	return $status;
}

sub IsIPRange {
	my $range=shift();
	if ($range =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}$/){
		return 1;
	} else {
		return 0;
	}
}

# ***************
# Toolkit Testing
# ***************

sub HaveTool {
	my $tool=shift();
	return 0 if (!$tool || ($tool =~ /[&\|\*\<\>\(\)\!\s\?#]/));
	my $r=system ("type $tool >/dev/null 2>&1");
	$r=$r>>8;
	return 1 if (!$r);
	return 0;
}

sub ToolVersion {
	my $tool=shift();
	return 0 if (!$tool || ($tool =~ /[&\|\*\<\>\(\)\!\s\?#]/));
	my $versionflag=shift();
	return 0 if (!$versionflag || ($versionflag =~ /[&\|\*\<\>\(\)\!\s\?#]/));
	my $versionrx=shift();
	$versionrx="\\d{1,}\\.\\d{1,}[\\.\\d{1,}]??" if (!$versionrx);
	my @v=`$tool $versionflag 2>&1`;
	my $version;
	for my $l (@v){
		next if (!$l || ($l !~ /\S/));
		if ($l =~ /$versionrx/){
			$version=$l;
			$version =~ s/[\s\S]+($versionrx)[\s\S]+/$1/g;;
			return $version;
		}
	}
	return 0;
}

sub ToolCheck {
	my $tool=shift();
	return 0 if (!$tool || ($tool =~ /[&\|\*\<\>\(\)\!\s\?#]/));
	if (HaveTool($tool)){
		my $version = ToolVersion($tool,'-V');
		print "Got $tool version $version\n";
	} else {
		print "$tool not installed or not in \$PATH\n";
	}
}

# ******************
# Neet Plugin XML file parsing
# ******************

package NeetXML;

use XML::Parser;

sub new {
	my $PKG=shift();
	my $file=shift();
	my %XML=();
	# Parse the XML plugins data file
	no warnings;
	my %tmp=();
	my %batch=();

	sub _xml_start {
		my( $expat, $element, %attrs ) = @_;
		if(("$element" eq "plugin") && %attrs ) {
			%tmp=%attrs;
		}
		if(("$element" eq "batch") && %attrs ) {
			%batch=%attrs;
		}
	}

	sub _xml_char {
		my( $expat, $data ) = @_;
		if ($data =~ /\S/){
			$XML{"$data"}{'desc'}=$tmp{'desc'} if ($tmp{'desc'});
			$XML{"$data"}{'msref'}=$tmp{'msref'} if ($tmp{'msref'});
			$XML{"$data"}{'cve'}=$tmp{'cve'} if ($tmp{'cve'});
			$XML{"$data"}{'bid'}=$tmp{'bid'} if ($tmp{'bid'});
			$XML{"$data"}{'type'}=$tmp{'type'} if ($tmp{'type'});
			$XML{"$data"}{'msf_exploit'}=$tmp{'msf_exploit'} if ($tmp{'msf_exploit'});
			$XML{"$data"}{'enabled'}=$tmp{'enabled'} if ($tmp{'enabled'});
			$XML{"$data"}{'data'}=$tmp{'data'} if ($tmp{'data'});
			$XML{"$data"}{'safe'}=$tmp{'safe'} if ($tmp{'safe'});
		}				
	}

	my $parser = XML::Parser->new( 'Handlers' => 
                                   {
                                    'Start'=>\&_xml_start,
										  							'Char'=>\&_xml_char,
                                   });	

	$parser->parsefile("$file");

	my $xmlobj=\%XML;
	bless $xmlobj, $PKG;
	return $xmlobj;
}

sub plugins {
	my $self=shift();
	my @plugins;
	for my $plugin (keys(%{$self})){
		push @plugins, $plugin if ("$plugin" ne "batch");
	}
	return @plugins;
}

sub batch {
	my $self=shift();
	return $$self{'batch'}{'data'};
}

sub desc {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'desc'};
}

sub type {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'type'};
}
sub msref {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'msref'};
}
sub cve {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'cve'};
}
sub bid {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'bid'};
}
sub msf_exploit {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'msf_exploit'};
}
sub isSafe {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'safe'};
}
sub enabled {
	my $self=shift();
	my $plugin=shift();
	return $$self{"$plugin"}{'enabled'};
}

1;
