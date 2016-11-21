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
	my $IP;
	return 0 if (!$Interface);
	for my $line (`ifconfig $Interface`){
		if ($line =~ /inet/){
			my ($junk,$ip,$junk2)=split ":", $line;
			($ip,$junk)=split "\\s", $ip;
			if (isIPSpec($ip)){
				$IP=$ip;
				last;
			}
		}
	}
	return $IP;
}

sub interfaceIP {
	my $interface=shift();
	return undef if (!isInterface($interface));
	my $ipconfig=`/sbin/ifconfig $interface | grep "inet addr"`;
	my $ipaddress=$ipconfig; $ipaddress=~s/^\s+inet addr:(\d+\.\d+\.\d+\.\d+)[\s\S]+$/$1/;
	return $ipaddress;
}

sub interfaceMask {
	my $interface=shift();
	return undef if (!isInterface($interface));
	my $ipconfig=`/sbin/ifconfig $interface | grep "inet addr"`;
	my $netmask=$ipconfig; $netmask=~s/^[\s\S]+Mask:(\d+\.\d+\.\d+\.\d+)[\s\S]+$/$1/;
	return $netmask;
}



1;
