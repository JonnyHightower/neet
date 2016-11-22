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

# This is JR::NetUtils.pm

sub isPortSpec {
	my $spec=shift();
	return 1 if ($spec =~ /^\d+[-,]??\d+$/);
	return 0;
}

sub isIPSpec {
	my $spec=shift();
	my $status=1;
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
			$status=0 if ($a !~ /^\d{1,3}$/);
			$status=0 if ($a > 255);
		}
	} else {
		# CIDR notation
		my ($net,$mask)=split "/", $spec;
		$status=is_ipspec($net);
		if ($status){
			if (!is_ipspec($mask)){
				if (!(($mask =~ /^\d+$/) && ($mask > 0) && ($mask < 33))){
					$status=0;
				}
			}
		}
	}
	return $status;
}

sub isIPRange {
	my $range=shift();
	if ($range =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}$/){
		return 1;
	} else {
		return 0;
	}
}

sub isInterface {
	my $interface=shift();
	return 0 if (!$interface || $interface =~ /\W/ || $interface !~ /\d/);
	my $rc=system("/sbin/ifconfig $interface >/dev/null 2>&1");
	$rc = $rc>>8;
	if ($rc == 0){
		return 1;
	}
	return 0;
}

sub InterfaceIP {
	my $Interface=shift();
	return 0 if (!$Interface);
	return 0 if (!isInterface($Interface));
	my @ifconfig=`/sbin/ip addr show`;
	my ($address,$mask,$broadcast,$mac,$object)=interfaceInfo ($Interface,@ifconfig);
	return $address;
}

sub interfaceIP {
	my $interface=shift();
	return undef if (!isInterface($interface));
	my @ifconfig=`/sbin/ip addr show`;
	my ($address,$mask,$broadcast,$mac,$object)=interfaceInfo ($interface,@ifconfig);
	return $address;
}

sub interfaceMask {
	my $interface=shift();
	return undef if (!isInterface($interface));
	my @ifconfig=`/sbin/ip addr show`;
	my ($address,$mask,$broadcast,$mac,$object)=interfaceInfo ($interface,@ifconfig);
	return $mask;
}

sub interfaceInfo {
	my $interface=shift();
	my @ifdata=@_;
	return undef if ($#ifdata < 6);

	if ("$interface" eq "list"){
		my @interfaces;
		for my $line (@ifdata){
			next if ($line !~ /^\d+:\s/);
			next if ($line =~ /state DOWN/);
			$line =~ m/\d:\s(\S+):\s+\<*/;
			push @interfaces, $1;
		}
		return @interfaces;
	}

	my $thisInterface=0;
	my ($address,$mask,$broadcast,$mac,$object);

	for my $line (@ifdata){
		if ($line =~ /\s$interface:\s/){
			$thisInterface=1;
			return undef if ($line =~ /state DOWN/);
			next;
		}
		if ($thisInterface){
			if ($line =~ /\sinet\s/){
				$line =~ m/^\s+inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s+brd\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s[\S\s]+$/;
				$address=$1;
				$broadcast=$2;
				next;
			}
			if ($line =~ /\slink\/ether\s/){
				$line =~ m/^\s+link\/ether\s(\S+)\s+brd\s+[\S\s]+/;
				$mac=$1;
				next;
			}
			if ($line =~ /^\d:/){
				$thisInterface=0;
				last;
			}
		}
	}

	if ($address){
		$object=NetAddr::IP->new($address);
		$mask=$object->mask();
		$address=$object->addr();
	}

	return ($address,$mask,$broadcast,$mac,$object);
}


1;
