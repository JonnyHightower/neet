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

# OutputParser.pm

# Parsers for common tool output
# Jonathan Roach
# April 2006
# Version


# ******************
# Credential File Parser
# ******************
package JR::Parsers::OutputParser::Credentials;

sub new {
	my $self=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");
	if (open(CRED,"$file")){
		my @_File=<CRED>;
		close CRED;
		for my $line (@_File){
			next if ($line !~ /\S/);
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %object;
	$object{'filename'}=$file;
	$object{'data'}=\@File;

	my $obj=\%object;
	bless $obj, $self;
	return $obj;
}

sub listType {
	my $self=shift();
	my $type=uc(shift());
	my @data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /^$type /){
			push @data, $line;
		}
	}
	return @data;
}

sub listAll {
	my $self=shift();
	my @data;
	for my $line (@{$$self{'data'}}){
		push @data, $line;
	}
	return @data;
}

sub _parse {
	my $self=shift();
	my $component=shift();
	my $data=shift();
	chomp $data;
	my $store;
	($store{'type'},$store{'service'},$store{'user'},$store{'pass'})=split (" ", $data, 4);
	if ($store{'service'} && ($store{'service'} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)){
		if ($store{'service'} =~ /:/){
			($store{'address'},$store{'port'},$store{'sid'})=split (":", $store{'service'},3);
		} else {
			$store{'address'}=$store{'service'};
		}
	} else {
		($store{'type'},$store{'user'},$store{'pass'})=split (" ", $data, 3);
	}
	return $store{$component};
}

sub type {
	my $self=shift();
	my $data=shift();
	return $self->_parse('type',$data);
}
sub service {
	my $self=shift();
	my $data=shift();
	my $svc=$self->_parse('service',$data);
	if ($svc && ($svc =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)){
		return $svc;
	}
	return 0;
}
sub address {
	my $self=shift();
	my $data=shift();
	if ($self->service($data)){
		return $self->_parse('address',$data);
	}
	return 0;
}
sub port {
	my $self=shift();
	my $data=shift();
	if ($self->service($data) =~ /:\d+/){
		return $self->_parse('port',$data);
	}
	return 0;
}
sub sid {
	my $self=shift();
	my $data=shift();
	if ($self->service($data) =~ /:\d+:\S/){
		return $self->_parse('sid',$data);
	}
	return undef;
}
sub account {
	my $self=shift();
	my $data=shift();
	return $self->_parse('user',$data);
}
sub password {
	my $self=shift();
	my $data=shift();
	return $self->_parse('pass',$data);
}
sub socket {
	my $self=shift();
	my $data=shift();
	my $a=$self->_parse('address',$data);
	my $p=$self->_parse('port',$data);
	if ($a && $p){
		return "$a:$p";
	}
	return 0;
}

# ******************
# netuserenum Parser
# ******************
package netuserenum;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");

	if (open(NUE,"$file")){
		my @_File=<NUE>;
		close NUE;
		my $_head=shift (@_File);
		for my $line (@_File){
			next if ($line =~ /^Making connection to OS:/);
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %object;
	$object{'filename'}=$file;
	$object{'data'}=\@File;

	my $obj=\%object;
	bless $obj, $pkg;
	return $obj;
}

sub ___unused {

	for my $line (@{$$self{'data'}}){
		next if ($line =~ /null connection/i || $line =~ /^Account Name\s+RID\s/);
		my ($user,$rid,$gid)=split "\\s+", substr($line,0,37);
		my $lastLogin=substr($line,36,24);
		my $lastLogoff=substr($line,61,24);
		$lastLogin="" if ($lastLogin =~ /No time specified/);
		$lastLogoff="" if ($lastLogoff =~ /No time specified/);
		my ($disabled,$badPasswords,$numLogons)=split "\\s+", substr($line,86,42);
		my $desc=substr($line,128,length($line)-129);
	}
}

sub ListUsers {
	my $self=shift();
	my @users;
	for my $line (@{$$self{'data'}}){
		next if ($line =~ /null connection/i || $line =~ /^Account Name\s+RID\s/);
		my ($user,$rid,$gid)=split "\\s+", substr($line,0,37);
		push @users, $user if ($user);
	}
	return @users;
}



# **************
# AMAP -m Parser
# **************
package Amap;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");

	if (open(AMAP,"$file")){
		my @_File=<AMAP>;
		close AMAP;
		my $_head=shift (@_File);
		if ($_head !~ /^# amap v\d\.\d \(www\.thc\.org/){
			return 0;
		}
		for my $line (@_File){
			next if ($line =~ /^#/);
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %amap;
	$amap{'filename'}=$file;
	$amap{'data'}=\@File;

	my $amapobj=\%amap;
	bless $amapobj, $pkg;
	return $amapobj;
}

sub Target {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $target if (($match == $c) && $target =~ /^(\d{1,3}\.){3}\d{1,3}$/);
	}
	return 0;
}

sub Port {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $port if (($match == $c) && $port =~ /^\d{1,}$/);
		$c++;
	}
	return 0;
}

sub Protocol {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $protocol if (($match == $c) && $protocol);
		$c++;
	}
	return 0;
}

sub PortStatus {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $status if (($match == $c) && $status);
		$c++;
	}
	return 0;
}

sub SSL {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return 1 if (($match == $c) && $SSL);
		$c++;
	}
	return 0;
}

sub Identification {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $id if (($match == $c) && $id);
		$c++;
	}
	return 0;
}

sub BannerAscii {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $printbanner if (($match == $c) && $printbanner);
		$c++;
	}
	return 0;
}

sub BannerHex {
	my $self=shift();
	my $match=shift();
	$match=1 if (!$match);
	my $c=1;
	for my $line (@{$$self{'data'}}){
		my ($target,$port,$protocol,$status,$ssl,$id,$printbanner,$hexbanner)=split ":", $line;
		return $hexbanner if (($match == $c) && $hexbanner);
		$c++;
	}
	return 0;
}

sub NumberMatches {
	my $self=shift();
	return $#{$$self{'data'}}+1;
}

# ******************
# END AMAP -m Parser
# ******************


# **************
# RPCINFO -p Parser
# **************

package RPCInfo;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");

	if (open(RPC,"$file")){
		my @_File=<RPC>;
		close RPC;
		my $_head=shift (@_File);
		if ($_head !~ /^\s+program\svers\sproto\s+port\s+$/){
			return 0;
		}
		for my $line (@_File){
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %rpc;
	$rpc{'filename'}=$file;
	$rpc{'rpcdata'}=\@File;

	my $rpcinfo=\%rpc;
	bless $rpcinfo, $pkg;
	return $rpcinfo;
}

sub ListTCPPorts {
	my $self=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if ("$prot" ne "tcp");
		my $_match=0;
		for my $p (@ports){
			if ($p && ($p == $port)){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub ListUDPPorts {
	my $self=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if ("$prot" ne "udp");
		my $_match=0;
		for my $p (@ports){
			if ($p && $p == $port){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub ListProgNames {
	my $self=shift();
	my @progs;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		my $_match=0;
		for my $p (@progs){
			if ($name && ($p eq $name)){
				$_match=1;
				last;
			}
		}
		if ($name && !$_match){
			push @progs, $name;
		}
	}
	return @progs;
}

sub ListProgNums {
	my $self=shift();
	my @progs;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		my $_match=0;
		for my $p (@progs){
			if ($p eq $num){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @progs, $num;
		}
	}
	return @progs;
}

sub ListPortsProgName {
	my $self=shift();
	my $_name=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if (!$name || ("$_name" ne "$name"));
		my $_match=0;
		for my $p (@ports){
			if ($p && $p == $port){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub ListPortsProgNameVer {
	my $self=shift();
	my $_name=shift();
	my $_ver=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if (!$name || ("$_name" ne "$name"));
		next if ("$_ver" ne "$ver");

		my $_match=0;
		for my $p (@ports){
			if ($p && $p == $port){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub ListPortsProgNum {
	my $self=shift();
	my $_num=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if ("$_num" ne "$num");
		my $_match=0;
		for my $p (@ports){
			if ($p && $p == $port){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub ListPortsProgNumVer {
	my $self=shift();
	my $_num=shift();
	my $_ver=shift();
	my @ports;
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if ("$_num" ne "$num");
		next if ("$_ver" ne "$ver");
		my $_match=0;
		for my $p (@ports){
			if ($p && $p == $port){
				$_match=1;
				last;
			}
		}
		if (!$_match){
			push @ports, $port;
		}
	}
	return @ports;
}

sub HaveProgName {
	my $self=shift();
	my $_prog=shift();
	for my $prog ($self->ListProgNames){
		return 1 if ($prog eq $_prog);
	}
	return 0;
}

sub HaveProgNameVer {
	my $self=shift();
	my $_prog=shift();
	my $_ver=shift();
	my @_a=$self->ListPortsProgNameVer($_prog,$_ver);
	return 1 if ($#_a >=0);
	return 0;
}

sub HaveProgNum {
	my $self=shift();
	my $_prog=shift();
	for my $prog ($self->ListProgNums){
		return 1 if ($prog eq $_prog);
	}
	return 0;
}

sub HaveProgNumVer {
	my $self=shift();
	my $_prog=shift();
	my $_ver=shift();
	my @_a=$self->ListPortsProgNumVer($_prog,$_ver);
	return 1 if ($#_a >=0);
	return 0;
}

sub HaveTCPPort {
	my $self=shift();
	my $_port=shift();
	for my $port ($self->ListTCPPorts){
		return 1 if ($port eq $_port);
	}
	return 0;
}

sub HaveUDPPort {
	my $self=shift();
	my $_port=shift();
	for my $port ($self->ListUDPPorts){
		return 1 if ($port eq $_port);
	}
	return 0;
}

sub TCPProg {
	my $self=shift();
	my $_port=shift();
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if (("$_port" ne "$port") || ("$prot" ne "tcp"));
		if ($name){
			return "$name";
		} else {
			return "$num";
		}
	}
	return 0;
}

sub UDPProg {
	my $self=shift();
	my $_port=shift();
	for my $service (@{$$self{'rpcdata'}}){
		my ($j,$num,$ver,$prot,$port,$name);
		if ($service =~ /^\s/){
			($j,$num,$ver,$prot,$port,$name)=split "\\s+", $service;
		} else {
			($num,$ver,$prot,$port,$name)=split "\\s+", $service;
		}
		next if (("$_port" ne "$port") || ("$prot" ne "udp"));
		if ($name){
			return "$name";
		} else {
			return "$num";
		}
	}
	return 0;
}

# ******************
# END RPCINFO Parser
# ******************

# ***************
# SNMP MIB Parser
# ***************
package snmp;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");
	if (open(SNMP,"$file")){
		my @_File=<SNMP>;
		close SNMP;
		if (!$_File[0] || ($_File[0] !~ /^SNMPv2-MIB::sysDescr.0/)){
			return 0;
		}
		my $tmp;
		for my $line (@_File){
			chomp $line;
			if ($line =~ /^[\s\S]{1,}-MIB::[\s\S]{1,}\.\d{1,} = /){
				if ($tmp){
					$tmp =~ s/[\r\n]/ /g;
					push @File, $tmp;
				}
				$tmp = $line;
			} else {
				$tmp .= $line;
			}
		}
		if ($tmp){
			$tmp =~ s/[\r\n]/ /g;
			push @File, $tmp;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %object;
	$object{'filename'}=$file;
	$object{'data'}=\@File;

	my $obj=\%object;
	bless $obj, $pkg;
	return $obj;
}

sub GetValue {
	my $self=shift();
	my $mib=shift();
	my $oid=shift();
	my ($junk, $value);
	for my $_oid (@{$$self{'data'}}){
		if ($_oid =~ /^${mib}::${oid} = /){
			($junk, $value) = split (" = ", $_oid);
			last;
		}
	}
	if ($value){
		$value =~ s/^INTEGER: //; $value =~ s/^STRING: //; 	$value =~ s/^Timeticks: //;
		$value =~ s/^OID: //; $value =~ s/^Gauge32: //;	$value =~ s/^Counter32: //;
		$value =~ s/^Hex-STRING: //; $value =~ s/^Network Address: //; $value =~ s/^IpAddress: //;
	}
	return $value;
}

sub EnumerateOids {
	my $self=shift();
	my $mib=shift();
	my $oid=shift();
	my ($junk, $value);
	my @oids;
	for my $_oid (@{$$self{'data'}}){
		if ($_oid =~ /^${mib}::${oid}\.\d{1,} = /){
			($junk, $value) = split (" = ", $_oid);
			push @oids, $junk
		}
	}
	return @oids;
}

sub SimilarOids {
	my $self=shift();
	my $mib=shift();
	my $oid=shift();
	my ($junk, $value);
	my @oids;
	for my $_oid (@{$$self{'data'}}){
		if ($_oid =~ /^${mib}::${oid}/){
			($junk, $value) = split (" = ", $_oid);
			push @oids, $junk
		}
	}
	return @oids;
}

sub GetValues {
	my $self=shift();
	my $mib=shift();
	my $oid=shift();
	my ($junk, $value);
	my @values;
	for my $_oid (@{$$self{'data'}}){
		if ($_oid =~ /^${mib}::${oid}/){
			($junk, $value) = split (" = ", $_oid);
			if ($value){
				$value =~ s/^INTEGER: //; $value =~ s/^STRING: //; 	$value =~ s/^Timeticks: //;
				$value =~ s/^OID: //; $value =~ s/^Gauge32: //;	$value =~ s/^Counter32: //;
				$value =~ s/^Hex-STRING: //; $value =~ s/^Network Address: //; $value =~ s/^IpAddress: //;
			}
			push @values, $value;
		}
	}
	return @values;
}

sub HostName {
	my $self=shift();
	my $hn=$self->GetValue("SNMPv2-MIB","sysName.0");
	return $hn;
}

sub DeviceClass {
	my $self=shift();
	my $dt=$self->GetValue("SNMPv2-MIB","sysDescr.0");
	my $class="PC";
	$class = "Server" if ($dt =~ /IBM PowerPC/);
	$class = "Printer" if ($dt =~ /JETDIRECT/);
	$class = "Router" if ($dt =~ /cisco systems/i);
	$class = "Switch" if ($dt =~ /switch/i);
	return $class;
}

sub OSFamily {
	my $self=shift();
	my $os=$self->GetValue("SNMPv2-MIB","sysDescr.0");
	my $OS="$os";
	$OS = "Cisco IOS" if ($os =~ /\sIOS\s/);
	$OS = "Windows" if ($os =~ / Windows /);
	$OS = "JetDirect" if ($os =~ /JETDIRECT/);
	$OS = "AIX" if ($os =~ /Runtime AIX/);
	$OS = "SCO Unix" if ($os =~ /^SCO /);
	$OS = "HP-UX" if ($os =~ /^HP-UX /);
	return $OS;
}

sub OSVersion {
	my $self=shift();
	my $os=$self->GetValue("SNMPv2-MIB","sysDescr.0");
	my $OSV="Unknown";
	if ($os =~ /\sIOS\s/){
		$OSV=$os;
		$OSV =~ s/^[\s\S]{1,}, Version (\d{1,}\.\d{1,}\(\d{1,}\)\w),[\s\S]{1,}/$1/;
	} elsif ($os =~ / Windows /){
		$OSV=substr($os,index($os,"Windows "),length($os)-index($os,"Windows "));

	} elsif ($os =~ /JETDIRECT/){
		$OSV = $os;
		if ($OSV !~ /ROM none/){
			$OSV =~ s/^[\s\S]{1,},(ROM \w\.\d\d\.\d\d),[\s\S]{1,}(EEPROM \w\.\d\d\.\d\d)[\s\S]{0,}$/$1,$2/;
		} else {
			$OSV =~ s/^[\s\S]{1,},(EEPROM \w\.\d\d\.\d\d)[\s\S]{0,}$/$1/;
		}
	} elsif ($os =~ /Runtime AIX/){
		$OSV = $os;
		$OSV =~ s/^[\s\S]{1,}ersion: (\d{1,}\.\d{1,}\.\d{1,}\.\d{1,})\D[\s\S]+/$1/;
		$OSV =~ s/0{1,}([1-9])/$1/g; $OSV =~ s/0{2,}/0/g;
	} elsif ($os =~ /^SCO /){
		$OSV = substr($os,index($os,"Release"),length($os)-index($os,"Release"));
	} elsif ($os =~ /^HP-UX /){
		$OSV = $os;
		$OSV =~ s/^HP-UX \w+ \w.(\d+\.\d+) \w \d+\/\d+ \d+/$1/;
	}
	return $OSV;
}

sub EnumerateInterfaces {
	my $self=shift();
	my $n=$self->GetValue("IF-MIB","ifNumber.0");
	my @interfaces;
	push @interfaces, $self->GetValues("IF-MIB","ifIndex.");

	# Get the IP data associated with the interfaces, and
	# store it in the object
	my %ipdata; my @ip_interfaces; my %routes; my @destinations;
	$$self{'ipdata'}=\%ipdata;
	$$self{'ipinterfaces'}=\@ip_interfaces;
	$$self{'routes'}=\%routes;
	$$self{'destinations'}=\@destinations;

	# IP Address
	for my $oid ($self->SimilarOids("IP-MIB","ipAdEntIfIndex.")){
		my ($mib,$_oid)=split "::", $oid;
		my $a=$self->GetValue("$mib","$_oid");
		if ($a){
			my $ip=$_oid; $ip =~ s/[\s\S]{1,}\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/$1.$2.$3.$4/;
			if ($ip){
				$ipdata{"$a"}{'IP'}=$ip;
				$ipdata{"$ip"}{'index'}=$a;
				push @ip_interfaces, $ip;
			}
		}
	}

	# Masks
	for my $ip (@ip_interfaces){
		my $mask = $self->GetValue("IP-MIB","ipAdEntNetMask.$ip");
		$ipdata{"$ip"}{'mask'}=$mask;
	}

	# Routes
	for my $oid ($self->SimilarOids("RFC1213-MIB","ipRouteDest.")){
		my ($mib,$_oid)=split "::", $oid;
		my $a=$self->GetValue("$mib","$_oid");
		if ($a){
			my $ip=$_oid; $ip =~ s/[\s\S]{1,}\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/$1.$2.$3.$4/;
			if ($ip){
				$routes{"$a"}{'IP'}=$ip;
				$routes{"$ip"}{'index'}=$a;
				push @destinations, $ip;
			}
		}
	}

	# Store data for all routes
	for my $ip (@destinations){
		my $if = $self->GetValue("RFC1213-MIB","ipRouteIfIndex.$ip");
		$routes{"$ip"}{'interface'}=$if;

		my $routemask = $self->GetValue("RFC1213-MIB","ipRouteMask.$ip");
		$routes{"$ip"}{'mask'}=$routemask;

		my $metric = $self->GetValue("RFC1213-MIB","ipRouteMetric1.$ip");
		$routes{"$ip"}{'metric'}=$metric;

		my $nexthop = $self->GetValue("RFC1213-MIB","ipRouteNextHop.$ip");
		$routes{"$ip"}{'nexthop'}=$nexthop;
	}
	return @interfaces;
}

sub Forwarding {
	my $self=shift();
	my $f=0;
	my $a=$self->GetValue("IP-MIB","ipForwarding.0");
	if ($a && $a =~ /forwarding\(1\)/){
		return 1;
	}
	return 0;
}

sub ListIPInterfaces {
	my $self=shift();
	my @i=$self->EnumerateInterfaces;
	my @ipif;
	for my $a (@i){
		if ($self->InterfaceIP($a)){
			push @ipif, $a;
		}
	}
	return @ipif;
}

sub InterfaceName {
	my $self=shift();
	my $interface=shift();
	return $self->GetValue("IF-MIB","ifName.$interface");
}

sub InterfaceDesc {
	my $self=shift();
	my $interface=shift();
	return $self->GetValue("IF-MIB","ifDescr.$interface");
}

sub InterfaceAlias {
	my $self=shift();
	my $interface=shift();
	return $self->GetValue("IF-MIB","ifAlias.$interface");
}

sub InterfaceType {
	my $self=shift();
	my $interface=shift();
	return $self->GetValue("IF-MIB","ifType.$interface");
}

sub InterfaceMAC {
	my $self=shift();
	my $interface=shift();
	my $_mac=$self->GetValue("IF-MIB","ifPhysAddress.$interface");
	$_mac =~ s/:(\d):/:0$1:/g;
	$_mac =~ s/^(\d):/0$1:/g;
	$_mac =~ s/:(\d)$/:0$1/g;
	return $_mac;
}

sub InterfaceIP {
	my $self=shift();
	my $interface=shift();
	return $$self{'ipdata'}{$interface}{'IP'};
}

sub InterfaceMask {
	my $self=shift();
	my $interface=shift();
	if ($interface =~ /\./){
		return $$self{'ipdata'}{$interface}{'mask'};
	} else {
		my $ip=$self->InterfaceIP($interface);
		return $$self{'ipdata'}{$ip}{'mask'};
	}
}

sub ListRoutes {
	my $self=shift();
	return @{$$self{'destinations'}};
}

sub RouteIF {
	my $self=shift();
	my $route=shift();
	return $$self{'routes'}{$route}{'interface'};
}

sub RouteMask {
	my $self=shift();
	my $route=shift();
	return $$self{'routes'}{$route}{'mask'};
}

sub RouteNextHop {
	my $self=shift();
	my $route=shift();
	return $$self{'routes'}{$route}{'nexthop'};
}

sub RouteMetric {
	my $self=shift();
	my $route=shift();
	return $$self{'routes'}{$route}{'metric'};
}

sub ARPCache {
	my $self=shift();
	my $if=shift();
	my @arp;
	for my $oid ($self->SimilarOids("RFC1213-MIB","atPhysAddress.$if.1")){
		my ($mib,$_oid)=split "::", $oid;
		my $a=$self->GetValue("$mib","$_oid");
		if ($a){
			my $ip=$_oid; $ip =~ s/[\s\S]{1,}\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/$1.$2.$3.$4/;
			push @arp, $ip if ($ip);
		}
	}
	return @arp;
}

sub ARPCacheMAC {
	my $self=shift();
	my $interface=shift();
	my $ip=shift();
	my $_mac=$self->GetValue("RFC1213-MIB","atPhysAddress.$interface.1.$ip");
	if (!$_mac){
		$_mac=$self->GetValue("RFC1213-MIB","atPhysAddress.$interface.$ip");
	}
	if ($_mac){
		$_mac =~ s/ /:/g;
		$_mac =~ s/:$//;
	}
	return $_mac;
}


sub Processes {
	my $self=shift();
	my @pids;
	for my $pid ($self->SimilarOids("HOST-RESOURCES-MIB","hrSWRunName.")){
		$pid =~ s/^[\s\S]+\.(\d{1,})$/$1/;
		push @pids, $pid;
	}
	return @pids;
}

sub ProcessName {
	my $self=shift();
	my $pid=shift();
	my $name=$self->GetValue("HOST-RESOURCES-MIB","hrSWRunName.$pid");
	$name =~ s/\"//g;
	return $name;
}

sub Software {
	my $self=shift();
	my @sw;
	for my $pkg ($self->GetValues("HOST-RESOURCES-MIB","hrSWInstalledName.")){
		$pkg =~ s/\"//g;
		push @sw, $pkg;
	}
	return @sw;
}

sub ListeningTCP {
	my $self=shift();
	my @ports; 
	#RFC1213-MIB::tcpConnState.0.0.0.0.1008.0.0.0.0.
	for my $port ($self->SimilarOids("RFC1213-MIB","tcpConnState.0.0.0.0.")){
		my ($mib,$_oid)=split "::", $port;
		my $a=$self->GetValue("$mib","$_oid");
		if ($a && $a =~ /listen/){
			$port =~ s/^[\s\S]+State.0.0.0.0.(\d{1,})[\s\S]+/$1/;
			push @ports, $port;
		}
	}
	return @ports;
}

sub EstablishedTCP {
	my $self=shift();
	my @ports; 
	for my $port ($self->SimilarOids("RFC1213-MIB","tcpConnState.")){
		my ($mib,$_oid)=split "::", $port;
		my $a=$self->GetValue("$mib","$_oid");
		#RFC1213-MIB::tcpConnState.166.154.6.1.513.166.154.60.63.1023
		if ($a && $a =~ /established/){
			$port =~ s/^[\s\S]+State.(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).(\d{1,}).(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).(\d{1,})/$1:$2 $3:$4/;
			push @ports, $port;
		}
	}
	return @ports;
}

sub ClosingTCP {
	my $self=shift();
	my @ports; 
	for my $port ($self->SimilarOids("RFC1213-MIB","tcpConnState.")){
		my ($mib,$_oid)=split "::", $port;
		my $a=$self->GetValue("$mib","$_oid");
		#RFC1213-MIB::tcpConnState.166.154.6.1.513.166.154.60.63.1023
		if ($a && $a =~ /timeWait/){
			$port =~ s/^[\s\S]+State.(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).(\d{1,}).(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).(\d{1,})/$1:$2 $3:$4/;
			push @ports, $port;
		}
	}
	return @ports;
}

#******************************
# Windows Tools - CPCE
#******************************

# **************
# nbtstat Parser
# **************
package nbtstat;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");

	if (open(NUE,"$file")){
		my @_File=<NUE>;
		close NUE;
		my $_head=shift (@_File);
		for my $line (@_File){
			next if ($line =~ /^Node IpAddress:/);
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %object;
	$object{'filename'}=$file;
	$object{'data'}=\@File;

	my $obj=\%object;
	bless $obj, $pkg;
	return $obj;
}

sub workstationName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<00>/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub netbiosName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<00>/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub serverName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<20>/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub netmonName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<BE>/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub netddeName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<1F>/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub userName {
	my $self=shift();
	my $hostname=$self->netbiosName;
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<03>/ || $line =~ /$hostname/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub messengerName {
	my $self=shift();
	my $hostname=$self->netbiosName;
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<03>/ || $line !~ /$hostname/ || $line =~ /~/);
		if ($line =~ /\sUNIQUE\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub domainName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<00>/ || $line =~ /~/);
		if ($line =~ /\sGROUP\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub domainMasterBrowserName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<1B>/ || $line =~ /~/);
		if ($line =~ /\sGROUP\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub domainControllerName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<1C>/ || $line =~ /~/);
		if ($line =~ /\sGROUP\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub segmentMasterBrowserName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<1D>/ || $line =~ /~/);
		if ($line =~ /\sGROUP\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub serverBrowserName {
	my $self=shift();
	my $name;
	for my $line (@{$$self{'data'}}){
		next if ($line !~ /\sRegistered\s/ || $line !~ /<1E>/ || $line =~ /~/);
		if ($line =~ /\sGROUP\s/){
			$name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
			return $name;
		}
	}
	return undef;
}

sub cachedNames {
	my $self=shift();
	my @names;
	for my $line (@{$$self{'data'}}){
		next if ($line =~ /\sRegistered\s/ || $line !~ /<00>/ || $line !~ /\sUNIQUE\s/ || $line =~ /~/);
		my $name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
		push @names, $name;

	}
	return @names;
}

sub broadcastResolvedNames {
	my $self=shift();
	my @names;
	for my $line (@{$$self{'data'}}){
		next if ($line =~ /\sRegistered\s/ || $line !~ /<00>/ || $line =~ /\sUNIQUE\s/ || $line =~ /\sGROUP\s/ || $line =~ /~/);
		my $name=$line; $name =~ s/^\s+(\S+)\s[\s\S]+$/$1/;
		push @names, $name;
	}
	return @names;
}

sub resolveName {
	my $self=shift();
	my $nbname=uc(shift());
	my $ip;
	for my $line (@{$$self{'data'}}){
		next if ($line =~ /\sRegistered\s/ || $line !~ /<00>/ || $line !~ /\s$nbname\s/ || $line =~ /~/);
		$ip=$line; $name =~ s/^[\s\S]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s\S]+$/$1/;
		return $ip;
	}
	return undef;
}

# **************
# Enum Parser
# **************
package enum;

sub new {
	my $pkg=shift();
	my $file=shift();
	my @File;
	return 0 if (! -f "$file");

	if (open(NUE,"$file")){
		my @_File=<NUE>;
		close NUE;
		my $_head=shift (@_File);
		for my $line (@_File){
			chomp $line;
			push @File, $line;
		}
		$#_File=-1;
	} else {
		return 0;
	}

	my %object;
	$object{'filename'}=$file;
	$object{'data'}=\@File;

	my $obj=\%object;
	bless $obj, $pkg;
	return $obj;
}

sub passwordMinLength {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Min Length:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub passwordMinAge {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Min Age:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub passwordMaxAge {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Max Age:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub passwordLockoutThreshold {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Lockout Threshold:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub passwordLockoutDuration {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Lockout Duration:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub passwordLockoutReset {
	my $self=shift();
	my $data;
	for my $line (@{$$self{'data'}}){
		if ($line =~ /\s+Lockout Reset:\s/i){
			$data=lc($line);# $data =~ s/^[\s\S]+:\s(\S+)\s+$/$1/;
			last;
		}
	}
	return $data;
}

sub users {
	my $self=shift();
	my @objects; my $indata=0;
	for my $line (@{$$self{'data'}}){
		if (!$indata && ($line =~ /\s+user list \(pass/i) && ($line =~ /Success/i)){
			$indata=1;
			next;
		}
		if ($indata && $line =~ /^\S/){
			last;
		}
		if ($indata){
			for my $obj (split "\\s", $line){
				push @objects, $obj if ($obj =~ /\S/);
			}
		}
	}
	return @objects;
}

sub shares {
	my $self=shift();
	my @objects; my $indata=0;
	for my $line (@{$$self{'data'}}){
		if (!$indata && ($line =~ /^enumerating shares /i) && ($line =~ / \d+ shares,/i)){
			$indata=1;
			next;
		}
		if ($indata && $line =~ /^\S/){
			last;
		}
		if ($indata){
			for my $obj (split "\\s", $line){
				push @objects, $obj if ($obj =~ /\S/);
			}
		}
	}
	return @objects;
}

sub groups {
	no warnings;
	my $self=shift();
	my (@groups, $group, @groupObjects);
	for my $line (@{$$self{'data'}}){
		if ($group && ( ($line !~ /\S/) || ($line =~ /^cleaning up\.\.\. /) ) ){
			addGroupMembers() if ($#groupObjects>=0);
			last;			
		}
		if ($line =~ /^Group: \S+/i){
			addGroupMembers() if ($#groupObjects>=0);
			$group=lc($line);
			my ($junk, $data)=split(" ",$group, 2);
			$group=$data;
			push @groups, $group;
			$#groupObjects=-1;
			next;
		}
		push @groupObjects, $line if ($group);
	}
	return @groups;

	sub addGroupMembers {
		# Adds group membership lists to the enum object
		my $_mem=join ",", @groupObjects;
		${$$self{"$group"}}="$_mem";
	}
}

sub groupMembers {
	my $self=shift();
	my $group=lc(shift());
	my @members;
	if (defined(${$$self{"$group"}})){
		@members=(split ",", ${$$self{"$group"}});
	}
	return @members;
}


















1;
