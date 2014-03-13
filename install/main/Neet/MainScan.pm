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

# MainScan.pm

# The Neet core
# Jonathan Roach

package Neet::MainScan;
use POSIX ":sys_wait_h";

sub new {
	my $pkg=shift();
	# The main object
	my %scan;

	# For Config file handling
	my $Config=shift();
	# Paths to binaries
	my $Binaries=shift();

	# For Log file handling
	my $Log=shift();

	# Routing data
	my (%routes,%interfaces);

	# Some details
	$scan{'BasePrefix'}=$Config->GetVal('BasePrefix');
	$scan{'Binaries'}=$Binaries;
	$scan{'MaxThreads'}=$Config->GetVal('MaxThreads');
	$scan{'Speed'}=$Config->GetVal('Speed');
	$scan{'Intensity'}=$Config->GetVal('Intensity');
	$scan{'Phases'}=$Config->GetVal('Phases');

	# Data stores
	my (@Addressranges,@ExcludeAddressranges,@OurAddressRanges,@TCPExcludes,@UDPExcludes,@IPExcludes,@localArpScans,@ExcludeOS,
		@Files,@ExcludeFiles,@HostStat,@VPNInterfaces,@LimitedGSMs,@DisabledGSMs,@ranges,@targetAddresses,@Interfaces,%Locality);

	# Store list of SDM Issues
	my (@SDMIssues,@SDMIssueTriggers);

	# Links to data stores
	$scan{'AddressRanges'}=\@AddressRanges;
	$scan{'ExcludeAddressRanges'}=\@ExcludeAddressRanges;
	$scan{'OurAddressRanges'}=\@OurAddressRanges;
	$scan{'InterfaceList'}=\@Interfaces;
	$scan{'ranges'}=\@ranges;
	$scan{'targetAddresses'}=\@targetAddresses;
	$scan{'localArpScans'}=\@localArpScans;

	$scan{'TCPIncludes'}=\@TCPIncludes;
	$scan{'UDPIncludes'}=\@UDPIncludes;
	$scan{'TCPExcludes'}=\@TCPExcludes;
	$scan{'UDPExcludes'}=\@UDPExcludes;

	$scan{'IncludeTCP'}=\@TCPIncludes;
	$scan{'IncludeUDP'}=\@UDPIncludes;
	$scan{'ExcludeTCP'}=\@TCPExcludes;
	$scan{'ExcludeUDP'}=\@UDPExcludes;

	$scan{'ExcludeOS'}=\@ExcludeOS;

	$scan{'LimitedGSMs'}=\@LimitedGSMs;
	$scan{'DisabledGSMs'}=\@DisabledGSMs;
	$scan{'VPNInterfaces'}=\@VPNInterfaces;
	$scan{'IPExcludes'}=\@IPExcludes;
	$scan{'Files'}=\@Files;
	$scan{'ExcludeFiles'}=\@ExcludeFiles;
	$scan{'HostStat'}=\@HostStat;
	$scan{'Routes'}=\%routes;
	$scan{'Locality'}=\%Locality;
	$scan{'Interfaces'}=\%interfaces;
	$scan{'SDMIssues'}=\@SDMIssues;
	$scan{'SDMIssueTriggers'}=\@SDMIssueTriggers;

	# Links to other objects
	$scan{'UDPPorts'}=PortRange->new();
	$scan{'TCPPorts'}=PortRange->new();
	$scan{'Config'}=$Config;
	$scan{'Log'}=$Log;

	# Scan Control
	$scan{'Resumed'}=0;
	$scan{'PreviousScan'}=0;
	$scan{'Paused'}=0;
	$scan{'Aborted'}=0;
	$scan{'Ran'}=0;
	$scan{'AutoExploit'}=0;
	$scan{'AIX'}=0;
	$scan{'Debug'}=0;
	$scan{'CommandTimeout'}=0;
	$scan{'PingScan'}=0;
	$scan{'Gentle'}=0;
	$scan{'ConnectScan'}=0;
	$scan{'CPUs'}=1;
	$scan{'ServiceDiscoveryComplete'}=0;

	# Note how many CPUs are in the system
	if (open(CPU,"/proc/cpuinfo")){
		$scan{'CPUs'}=0;
		until (eof CPU){
			my $line = readline(*CPU);
			$scan{'CPUs'}++ if ($line =~ /^processor/);
		}
		close CPU;
	}

	# Phasing
	$scan{'Phase'}=0;
	$scan{'CurrentPortRange'}=0;

	# Target Specification
	$scan{'NumRoutes'}=0;
	$scan{'Local'}=0;
	$scan{'Internet'}=0;
	$scan{'TotalTargets'}=0;
	$scan{'RangeIndex'}=0;

	# Directories
	$scan{'ControlDirectory'}=".neet";
	$scan{'ResultsDirectory'}=$ENV{'PWD'};
	$scan{'ResourceDirectory'}=$Config->GetVal("ResourceDirectory");
	$scan{'HelperDirectory'}=$scan{'BasePrefix'} . "/helpers/bin";

	# Status files
	$scan{'StatusFile'}=$scan{'ControlDirectory'} . "/global.nt";
	$scan{'HostStatusFile'}=$scan{'ControlDirectory'} . "/hoststat.nt";
	$scan{'CompletedFile'}=$scan{'ControlDirectory'} . "/sdmscomplete.nt";

	# Output Files
	$scan{'MasterIssuesFile'}=$scan{'ResultsDirectory'} . "/masterIssues.txt";

	# Module Control
	$scan{'LimitGSMs'}=0;
	$scan{'DisabledGSM'}=0;

	# Record interface information
	my $if;
	for my $line (`/sbin/ifconfig -a`){	
		if ($line =~ /^\w+\d+[\.\d+]{0,}\s+Link[\s\S]+/){
			$if=$line; $if =~ s/^(\w+\d+[\.\d+]{0,})\s+Link[\s\S]+/$1/;
		}
		if ($line =~ /inet addr/){
			my ($ip,$mask,$junk);
			my @ifconfig=split ":", $line;
			next if $#ifconfig !=3;
			($ip,$junk) = split /\s/, $ifconfig[1];
			$mask = $ifconfig[3]; chomp ($mask);
			$interfaces{$if}{'address'}=$ip;
			$interfaces{$if}{'mask'}=$mask;
			$interfaces{$if}{'object'}=NetAddr::IP->new($ip,$mask);
			push @InterfaceList, $if;
			push @OurAddressRanges, $ip;
		}
	}

	# List VPN Interfaces
	@{$scan{'VPNInterfaces'}} = split " ", $Config->GetVal("Interface.VPN");

	# Populate routing hash
	for my $route (`/sbin/route -n`){
		next if ($route !~ /^\d/);
		$route =~ s/\s+/ /g;
		if ($route !~ /^0.0.0.0 /){
			my ($dest,$gw,$mask,$flags,$metric,$ref,$use,$interface)=split " ", $route;
			$routes{$scan{'NumRoutes'}}{'Dest'}=$dest;
			$routes{$scan{'NumRoutes'}}{'GW'}=$gw;
			$routes{$scan{'NumRoutes'}}{'Mask'}=$mask;
			$routes{$scan{'NumRoutes'}}{'Metric'}=$metric;
			$routes{$scan{'NumRoutes'}}{'Interface'}=$interface;
			# For route calculations later
			$routes{$scan{'NumRoutes'}}{'NetSpec'}=NetAddr::IP->new($dest,$mask);
			$routes{$scan{'NumRoutes'}}{'NumHosts'}=$routes{$scan{'NumRoutes'}}{'NetSpec'}->num();
			#print "$scan{'NumRoutes'} D $dest G $gw M $mask m $metric $interface [ $routes{$scan{'NumRoutes'}}{'NumHosts'} ]\n";
			$scan{'NumRoutes'}++;
		} else {
			my ($dest,$gw,$mask,$flags,$metric,$ref,$use,$interface)=split " ", $route;
			$routes{'Default'}{'Dest'}=$dest;
			$routes{'Default'}{'GW'}=$gw;
			$routes{'Default'}{'Mask'}=$mask;
			$routes{'Default'}{'Metric'}=$metric;
			$routes{'Default'}{'Interface'}=$interface;
			# For route calculations later
			my $NetSpec=NetAddr::IP->new($dest,$mask);
			$routes{'Default'}{'NetSpec'}=$NetSpec;
			#print "$scan{'NumRoutes'} D $dest G $gw M $mask m $metric $interface\n";
		}
	}

	my $self=\%scan;
	bless $self, $pkg;
	return $self;
}

# Directory and status control
#------------------
sub getPath {
	my $self=shift();
	my $bin=shift();
	my $path=$$self{'Binaries'}->GetVal("$bin");
	return $path;
}

sub CreateControlDirectory {
	my $self=shift();
	if (! -d $$self{'ControlDirectory'}){
		system ("mkdir -p $$self{'ControlDirectory'}");
		if (-d "$$self{'ControlDirectory'}"){
			return 1;
		} else {
			return 0;
		}
	} else {
		return 1;
	}
}

sub ControlDirectory {
	my $self=shift();
	my $_dir=shift();
	if (!defined($_dir)){
		return $$self{'ControlDirectory'};
	} else {
		$$self{'ControlDirectory'} = $$self{'ResultsDirectory'} . "/" . $_dir;
		$$self{'StatusFile'}=$$self{'ControlDirectory'} . "/global.nt";
		$$self{'CompletedFile'}=$$self{'ControlDirectory'} . "/sdmscomplete.nt";
		$$self{'HostStatusFile'}=$$self{'ControlDirectory'} . "/hoststat.nt";
		return 0;
	}
}

sub ResultsDirectory {
	my $self=shift();
	return $$self{'ResultsDirectory'};
}

sub ResourceDirectory {
	my $self=shift();
	return $$self{'ResourceDirectory'};
}

sub HelperDirectory {
	my $self=shift();
	return $$self{'HelperDirectory'};
}

sub CompletedFile {
	my $self=shift();
	return $$self{'CompletedFile'};
}

sub StatusFile {
	my $self=shift();
	return $$self{'StatusFile'};
}

sub HostStatusFile {
	my $self=shift();
	return $$self{'HostStatusFile'};
}

sub Config {
	my $self=shift();
	return $$self{'Config'};
}

sub Log {
	my $self=shift();
	return $$self{'Log'};
}

sub BasePrefix {
	my $self=shift();
	return $$self{'BasePrefix'};
}

# Global Service Monitor loading. If an -m is specified on the command line
# Stop all GSMs except for those specified after -m flag.

sub LimitGsms {
	my $self=shift();
	my $limit=shift();
	if (!defined($limit)){
		return $$self{'LimitGSMs'};
	} else {
		$$self{'LimitGSMs'}=$limit if ($limit =~ /^[01]$/);
		return $$self{'LimitGSMs'};
	}
}
sub DisabledGsm {
	my $self=shift();
	my $disable=shift();
	if (!defined($disable)){
		return $$self{'DisabledGSM'};
	} else {
		$$self{'DisabledGSM'}=$disable if ($disable =~ /^[01]$/);
		return $$self{'DisabledGSM'};
	}
}
sub KidGloves {
	my $self=shift();
	my $gentle=shift();
	if (!defined($gentle)){
		return $$self{'Gentle'};
	} else {
		$$self{'Gentle'}=$gentle if ($gentle =~ /^[01]$/);
		return $$self{'Gentle'};
	}
}

sub addGsm {
	my $self=shift();
	my $module=shift();
	push @{$self{'LimitedGSMs'}}, $module;
}
sub delGsm {
	my $self=shift();
	my $module=shift();
	$$self{'DisabledGSM'}=1;
	push @{$self{'DisabledGSMs'}}, $module;
}

sub DisabledGsms {
	my $self=shift();
	if ($$self{'DisabledGSM'}){
		return @{$self{'DisabledGSMs'}};
	} else {
		return undef;
	}
}

sub isInterface {
	my $interface=shift();
	return 1 if (exists ($$self{'Interfaces'}{$interface}{'address'}));
	return 0;
	#return 0 if (!$interface || $interface =~ /\W/ || $interface !~ /\d/);
	#my $rc=system("/sbin/ifconfig $interface >/dev/null 2>&1");
	#$rc = $rc>>8;
	#if ($rc == 0){
	#	return 1;
	#}
	#return 0;
}

sub localArpScan {
	my $self=shift();
	my $interface=shift();
	if (!$interface){
		return @{$$self{'localArpScans'}};
	}
	if (isInterface($interface)){
		for my $i (@{$$self{'localArpScans'}}){
			if ($i eq $interface){
				return 0;
			}
		}
		push @{$$self{'localArpScans'}}, $interface;
		return 1;
	}
	return 0;
}

sub LimitedGsms {
	my $self=shift();
	return @{$self{'LimitedGSMs'}};
}


# **********************
# Target-Specific Parameters

sub SetHostDown {
	my $self=shift();
	my $target=shift();
	$target = $self->Target if (!defined($target));
	mkdir "$$self{'ControlDirectory'}/down";
	if (open($FH,">$$self{'ControlDirectory'}/down/$target")){
		close $FH;
		# Remove it from the live hosts file
		$self->DelStatKey("$$self{'ResultsDirectory'}/liveHosts.txt",$target);
		return 0;
	}
	#my $HostStatFile=$self->HostStatusFile;
	#if ($self->SetStatValue("$HostStatFile",$target,"down")){
	#	return 1;
	#}
	return 1;
}

sub SetHostNotDown {
	my $self=shift();
	my $target=shift();
	$target = $self->Target if (!defined($target));
	unlink "$$self{'ControlDirectory'}/down/$target";
	return 0;
	#my $HostStatFile=$self->HostStatusFile;
	#if ($self->DelStatKey("$HostStatFile",$target,"down")){
	#	return 1;
	#}
	#return 0;
}

sub IsHostUp {
	my $self=shift();
	my $target=shift();
	$target = $self->Target if (!defined($target));
	my $dir=$self->ResultsDirectory . "/$target";
	if (-d $dir){
		return 1;
	} else {
		return 0;
	}
}

sub IsHostDown {
	my $self=shift();
	my $target=shift();
	$target = $self->Target if (!defined($target));
	if (-f "$$self{'ControlDirectory'}/down/$target"){
		return 1;
	}
	return 0;
	#my $HostStatFile=$self->HostStatusFile;
	#my $status=$self->GetStatValue("$HostStatFile",$target);
	#if ($status && "$status" eq "down"){
	#	return 1;
	#} else {
	#	return 0;
	#}
}

sub IsHostCancelled {
	my $self=shift();
	my $target=shift();
	$target = $self->Target if (!defined($target));
	if (-f "$$self{'ResultsDirectory'}/${target}/.cancelled"){
		return 1;
	}
	#my $HostStatFile=$self->HostStatusFile;
	#my $status=$self->GetStatValue("$HostStatFile",$target);
	#if (defined($status) && (("$status" eq "cancel") || ("$status" eq "cancelall"))){
	#	return 1;
	#} else {
	#	return 0;
	#}
	return 0;
}

sub OSDetect {
	my $self=shift();
	my $osd=shift();
	if (!defined($osd)){
		return $$self{'OSDetect'};
	} else {
		$$self{'OSDetect'}=$osd;
	}
	return 1;
}

# **********************
# Port Range Definitions

sub NoBannerGrabPorts {
	my $self=shift();
	my $ports=shift();
	if (defined($ports)){
		$$self{'NoBannerGrabPorts'}=$ports;
		return 0;
	} else {
		return $$self{'NoBannerGrabPorts'};
	}
}

sub TCPPorts {
	my $self=shift();
	my $added=0;
	for my $range (@{$$self{'IncludeTCP'}}){
		$$self{'TCPPorts'}->Include($range);
		$added++;
	}
	if (!$added){
		$$self{'TCPPorts'}->Include($$self{'Config'}->GetVal('PortRange.Default.TCP'));
	}
	for my $range (@{$$self{'ExcludeTCP'}}){
		$$self{'TCPPorts'}->Exclude($range);
	}
	return $$self{'TCPPorts'}->RangeSpec();
}

sub UDPPorts {
	my $self=shift();
	my $added=0;
	for my $range (@{$$self{'IncludeUDP'}}){
		$$self{'UDPPorts'}->Include($range);
		$added++;
	}
	if (!$added){
		$$self{'UDPPorts'}->Include($$self{'Config'}->GetVal('PortRange.Default.UDP'));
	}
	for my $range (@{$$self{'ExcludeUDP'}}){
		$$self{'UDPPorts'}->Exclude($range);
	}
	return $$self{'UDPPorts'}->RangeSpec();
}

sub ExcludedTCPPorts {
	my $self=shift();
	return @{$$self{'ExcludeTCP'}};
}

sub ExcludedUDPPorts {
	my $self=shift();
	return @{$$self{'ExcludeUDP'}};
}

sub IncludeTCPPorts {
	my $self=shift();
	my $incrange=shift();
	return 0 if (!$incrange);
	push @{$$self{'IncludeTCP'}},$incrange;
	return 1;
}

sub IncludeUDPPorts {
	my $self=shift();
	my $incrange=shift();
	return 0 if (!$incrange);
	push @{$$self{'IncludeUDP'}},$incrange;
	return 1;
}

sub ExcludeTCPPorts {
	my $self=shift();
	my $excrange=shift();
	return 0 if (!$excrange);
	push @{$$self{'ExcludeTCP'}},$excrange;
	return 1;
}

sub ExcludeUDPPorts {
	my $self=shift();
	my $excrange=shift();
	return 0 if (!$excrange);
	push @{$$self{'ExcludeUDP'}},$excrange;
	return 1;
}

sub NoAIX {
	my $self=shift();
	$$self{'TCPPorts'}->Exclude($$self{'Config'}->GetVal("PortRange.Exclude.TCP.AIXHACMP"));
	$$self{'UDPPorts'}->Exclude($$self{'Config'}->GetVal("PortRange.Exclude.UDP.AIXHACMP"));
	$$self{'AIX'}=1;
	return 1;
}

sub SetCurrentPortRange {
	my $self=shift();
	my $range=shift();
	if (!$range){
		return 0;
	}
	if ($range =~ /^(\d+[-,]??\d+){1,}$/){
		$$self{'CurrentPortRange'}=$range;
		return 1;
	} else {
		return 0;
	}
}

sub CurrentPortRange {
	my $self=shift();
	return $$self{'CurrentPortRange'};
}

# IP RANGE SETUP

sub toShortRangeNotation {
	my $self=shift();
	my $range1=shift();
	my $range2=shift();
	return 0 if (!$range2);
	my @o1=split "\\.", $range1;
	my @o2=split "\\.", $range2;
	my @new;
	for (my $a=0; $a<4; $a++){
		if ($o1[$a] == $o2[$a]){
			push @new, $o1[$a];
		} else {
			push @new, $o1[$a] . "-" . $o2[$a];
		}
	}
	return join "." , @new;
}

sub AddAddress {
	my $self=shift();
	my $range=shift();
	return 0 if (!$range);
	$range =~ s/\*/0-255/g;
	if ($range =~ /\//){
		my $NetSpec=NetAddr::IP->new($range);
		my $start=substr($NetSpec->first(),0,index($NetSpec->first(),"/"));
		my $last=substr($NetSpec->last(),0,index($NetSpec->last(),"/"));
		my $newrange=$self->toShortRangeNotation($start,$last);
		push @{$$self{'AddressRanges'}}, $newrange;
	} else {
		push @{$$self{'AddressRanges'}}, $range;
	}
	return 1;
}

sub DeleteAddress {
	my $self=shift();
	my $range=shift();
	return 0 if (!$range);
	$range =~ s/\*/0-255/g;
	my $remove;
	if ($range =~ /\//){
		my $NetSpec=NetAddr::IP->new($range);
		my $start=substr($NetSpec->first(),0,index($NetSpec->first(),"/"));
		my $last=substr($NetSpec->last(),0,index($NetSpec->last(),"/"));
		my $newrange=$self->toShortRangeNotation($start,$last);
		$remove=$newrange;
	} else {
		$remove=$range;
	}
	my @temp=@{$$self{'AddressRanges'}};
	$#{$$self{'AddressRanges'}}=-1;
	for my $range (@temp){
		if ("$range" ne "$remove"){
			push @{$$self{'AddressRanges'}}, $range;
		}
	}
	return 1;
}

sub ExclAddress {
	my $self=shift();
	my $range=shift();
	return 0 if (!$range);
	$range =~ s/\*/0-255/g;
	if ($range =~ /\//){
		my $NetSpec=NetAddr::IP->new($range);
		my $start=substr($NetSpec->first(),0,index($NetSpec->first(),"/"));
		my $last=substr($NetSpec->last(),0,index($NetSpec->last(),"/"));
		my $newrange=$self->toShortRangeNotation($start,$last);
		push @{$$self{'ExcludeAddressRanges'}}, $newrange;
	} else {
		push @{$$self{'ExcludeAddressRanges'}}, $range;
	}
	$$self{'Excludes'}=1;
	return 1;
}

sub TotalTargets {
	my $self=shift();
	return $$self{'TotalTargets'};
}

sub AddressRanges {
	my $self=shift();
	return @{$$self{'AddressRanges'}};
}

sub Files {
	my $self=shift();
	return @{$$self{'Files'}};
}

sub ExcludeFiles {
	my $self=shift();
	return @{$$self{'ExcludeFiles'}};
}

sub AddFile {
	my $self=shift();
	my $file=shift();
	if (open(FILE,"$file")){
		push @{$$self{'Files'}}, $file;
		until (eof FILE){
			my $inrange=readline(*FILE);
			$inrange =~ s/[\r\n]//g;
			next if (!$self->IsIPSpec($inrange));
			$self->AddAddress($inrange);
		}
		close FILe;
		return 1;
	}
	return 0;
}

sub AddExcludeFile {
	my $self=shift();
	my $file=shift();
	if (open(FILE,"$file")){
		push @{$$self{'ExcludeFiles'}}, $file;
		until (eof FILE){
			my $inrange=readline(*FILE);
			$inrange =~ s/[\r\n]//g;
			next if (!$self->IsIPSpec($inrange));			
			$self->ExclAddress($inrange);
		}
		close FILe;
		return 1;
	}
	return 0;
}

sub ExcludedAddressRanges {
	my $self=shift();
	return @{$$self{'ExcludeAddressRanges'}};
}

sub IsIPSpec {
	my $self=shift();
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
			if ("$a" ne "*"){
				$status=0 if ($a !~ /^\d{1,3}$/);
				$status=0 if (($a < 0) || ($a > 255));
			}
		}
	}
	return $status;
}

sub ProcAddresses {
	my $self=shift();
	$#{$$self{'ranges'}}=-1;
	$$self{'TotalTargets'}=0;
	$$self{'GetNextAddressEndStop'}=0;
	for my $inrange ( @{$$self{'AddressRanges'}} ){
		my $range=addressRange->new($inrange);
		for my $exrange ( @{$$self{'OurAddressRanges'}} ){
			$range->exclude($exrange);
		}
		for my $exrange ( @{$$self{'ExcludeAddressRanges'}} ){
			$range->exclude($exrange);
		}
		if ($range->numAddresses >= 1){
			$range->addressList;
			$$self{'TotalTargets'}+=$range->numAddresses;
			push @{$$self{'ranges'}}, $range;
		}
	}
	return 0;
}

# Address generation
sub GetNextAddress {
	my $self=shift();
	if ($$self{'GetNextAddressEndStop'}){
		return undef;
	}
	my $range=@{$$self{'ranges'}}[$$self{'RangeIndex'}];
	return undef if (!defined($range));
	my $ip=$range->getNextAddress;
	if (!$ip){
		# Must be at the end of the range. Wrap.
		$range->reset;
		$$self{'RangeIndex'}++;
		$range=@{$$self{'ranges'}}[$$self{'RangeIndex'}];
		if (defined($range)){
			$ip=$range->getNextAddress;
		}
	}
	if (!$ip){
		# Must have come to the end
		$$self{'RangeIndex'}=0; # This provides wrap-around
		$$self{'GetNextAddressEndStop'}=1;
		return undef;
	}

	# Determine which route to use for this target
	$$self{'Local'}=0;
	$$self{'VPN'}=0;
	my ($chosen,$minHosts,$favourite)=(0,99999999999,0);
	my $HostObj=NetAddr::IP->new($ip,"255.255.255.255");

	for (my $a=0; $a < $$self{'NumRoutes'}; $a++){
		my $route=$$self{'Routes'}{$a}{'Dest'};
		my $mask=$$self{'Routes'}{$a}{'Mask'};
		my $gateway=$$self{'Routes'}{$a}{'GW'};
		#print "$a $ip : $route $mask ($gateway)\n";
		if ($$self{'Routes'}{$a}{'NetSpec'}->contains($HostObj)){
			if ($$self{'Routes'}{$a}{'NumHosts'} < $minHosts){
				# We have a route. Record it.
				#print "Found a route to $ip (route $a)\n";
				$favourite=$a; $minHosts=$$self{'Routes'}{$a}{'NumHosts'};
				$chosen=1;
			}
		}
	}

	if ($chosen){
		# We chose at least one route
		$$self{'Interface'}=$$self{'Routes'}{$favourite}{'Interface'};
	} else {
		# Failed to pick a route from the ones above. Use the default route.
		$$self{'Interface'}=$$self{'Routes'}{'Default'}{'Interface'};
	}

	# Determine if the target is on a local interface or not
	if ($$self{'Interfaces'}{$$self{'Interface'}}{'object'}->contains($HostObj)){
		$$self{'Local'}=1;
	}

	# Now see if our chosen route is over a VPN - set a flag if it is
	for my $if (@{$$self{'VPNInterfaces'}}){
		if ($$self{'Interface'} =~ /^$if\d+/){
			$$self{'VPN'}=1;
			last;
		}
	}

	# Store the locality information for use by the modules
	$$self{'Locality'}{$ip}{'interface'}=$$self{'Interface'};
	$$self{'Locality'}{$ip}{'vpn'}=0;
	$$self{'Locality'}{$ip}{'locality'}="remote";
	$$self{'Locality'}{$ip}{'locality'}="internet" if (($$self{'Internet'}) && (!$$self{'VPN'}) && (!$$self{'Local'}));
	if ($$self{'VPN'}){
		$$self{'Locality'}{$ip}{'locality'}="vpn";
		$$self{'Locality'}{$ip}{'vpn'}=1;
	}
	$$self{'Locality'}{$ip}{'locality'}="local" if ($$self{'Local'});

	$$self{'Target'}=$ip;
	return $ip;
}

sub IsHostLocal {
	my $self=shift();
	my $ip=shift();

	return (0,0) if (!$ip);
	if (!exists($$self{'Locality'}{$ip}{'locality'})){
		# Determine which route to use for this target
		$$self{'Local'}=0;
		$$self{'VPN'}=0;
		my ($chosen,$minHosts,$favourite)=(0,99999999999,0);
		my $HostObj=NetAddr::IP->new($ip,"255.255.255.255");

		for (my $a=0; $a < $$self{'NumRoutes'}; $a++){
			my $route=$$self{'Routes'}{$a}{'Dest'};
			my $mask=$$self{'Routes'}{$a}{'Mask'};
			my $gateway=$$self{'Routes'}{$a}{'GW'};
			#print "$a $ip : $route $mask ($gateway)\n";
			if ($$self{'Routes'}{$a}{'NetSpec'}->contains($HostObj)){
				if ($$self{'Routes'}{$a}{'NumHosts'} < $minHosts){
					# We have a route. Record it.
					#print "Found a route to $ip (route $a)\n";
					$favourite=$a; $minHosts=$$self{'Routes'}{$a}{'NumHosts'};
					$chosen=1;
				}
			}
		}

		if ($chosen){
			# We chose at least one route
			$$self{'Interface'}=$$self{'Routes'}{$favourite}{'Interface'};
		} else {
			# Failed to pick a route from the ones above. Use the default route.
			$$self{'Interface'}=$$self{'Routes'}{'Default'}{'Interface'};
		}

		# Determine if the target is on a local interface or not
		if ($$self{'Interfaces'}{$$self{'Interface'}}{'object'}->contains($HostObj)){
			$$self{'Local'}=1;
		}

		# Now see if our chosen route is over a VPN - set a flag if it is
		for my $if (@{$$self{'VPNInterfaces'}}){
			if ($$self{'Interface'} =~ /^$if\d+/){
				$$self{'VPN'}=1;
				last;
			}
		}

		# Store the locality information for use by the modules
		$$self{'Locality'}{$ip}{'interface'}=$$self{'Interface'};
		$$self{'Locality'}{$ip}{'vpn'}=0;
		$$self{'Locality'}{$ip}{'locality'}="remote";
		$$self{'Locality'}{$ip}{'locality'}="internet" if (($$self{'Internet'}) && (!$$self{'VPN'}) && (!$$self{'Local'}));
		if ($$self{'VPN'}){
			$$self{'Locality'}{$ip}{'locality'}="vpn";
			$$self{'Locality'}{$ip}{'vpn'}=1;
		}
		$$self{'Locality'}{$ip}{'locality'}="local" if ($$self{'Local'});
		$$self{'Target'}=$ip;
	}

	return ($$self{'Locality'}{$ip}{'locality'},$$self{'Locality'}{$ip}{'interface'});
}
sub IsHostVPN {
	my $self=shift();
	my $ip=shift();
	return $$self{'Locality'}{$ip}{'vpn'};
}

# User Options

sub ExcludedOS {
	my $self=shift();
	return @{$$self{'ExcludeOS'}};
}
sub ExcludeOS {
	my $self=shift();
	my $os=shift();
	return 0 if (!$os);
	push @{$$self{'ExcludeOS'}},$os;
	return 1;
}

sub Debug {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'Debug'};
	} else {
		$$self{'Debug'}=$num;
		return 1;
	}
}

sub PingScan {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'PingScan'};
	} else {
		$$self{'PingScan'}=$num;
		return 1;
	}
}

sub ConnectScan {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'ConnectScan'};
	} else {
		$$self{'ConnectScan'}=$num;
		return 1;
	}
}

sub AutoExploit {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'AutoExploit'};
	} else {
		$$self{'AutoExploit'}=$num;
		return 1;
	}
}

sub Speed {
	my $self=shift();
	my $speed=shift();
	if (!$speed){
		return $$self{'Speed'};
	} else {
		$$self{'Speed'}=$speed;
		return 1;
	}
}

sub Intensity {
	my $self=shift();
	my $intensity=shift();
	if (!$intensity){
		return $$self{'Intensity'};
	} else {
		$$self{'Intensity'}=$intensity;
		return 1;
	}
}

sub Internet {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'Internet'};
	} else {
		$$self{'Internet'}=$num;
		return 1;
	}
}

sub VPN {
	my $self=shift();
	my $num=shift();
	if (!defined($num) || $num !~ /^\d$/){
		return $$self{'VPN'};
	} else {
		$$self{'VPN'}=$num;
		return 1;
	}
}

sub Interface {
	my $self=shift();
	return $$self{'Interface'};
}

# Target information

sub Target {
	my $self=shift();
	return $$self{'Target'};
}

sub AIX {
	my $self=shift();
	return $$self{'AIX'};
}

sub TargetLocal {
	my $self=shift();
	return $$self{'Local'};
}

# Determine if the target has been deemed live or not
sub TargetLive {
	my $self=shift();
	my $target=shift();
	return $self->GetStatKey("$$self{'ResultsDirectory'}/liveHosts.txt","$target");
}

# Determine if anything is scanning the specified IP address
sub ScansInProgress {
	my $self=shift();
	my $target=shift();
	my $result=0;
	$self->System("ps x | grep $target | grep -v grep > \"raw/processList.txt\"");
	my @processList=$self->ReadFile("$$self{'ResultsDirectory'}/${target}/raw/processList.txt");
	for my $process (@processList){
		if ($process =~ /\s$target\s/){ # && (($process =~ /\sNeet\s/) || ($process =~ /nmap\s/)) ){
			$result++;
		}
	}
	return $result;
}

# Scan Status

sub SetPhase {
	my $self=shift();
	my $phase=shift();
	if (defined($phase)){
		$$self{'Phase'}=$phase;
		return 1;
	}
	return 0;
}

sub Phase {
	my $self=shift();
	return $$self{'Phase'};
}

sub Phases {
	my $self=shift();
	return $$self{'Phases'};
}

sub PreviousCommandLine {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if (my $val=$self->GetStatValue($StatusFile,"commandline")){
		return $val;
	}
	return 0;
}

sub StoreCommandLine {
	my $self=shift();
	my $cmd=shift();
	my $StatusFile=$self->StatusFile;
	if ($self->SetStatValue($StatusFile,"commandline","$cmd")){
		return 1;
	}
	return 0;
}

sub WasPaused {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if (my $val=$self->GetStatValue($StatusFile,"status")){
		return 1 if ($val && ("$val" eq "paused"));
	}
	return 0;
}

sub HadFinished {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if (my $val=$self->GetStatValue($StatusFile,"status")){
		return 1 if ($val && ("$val" eq "finished"));
	}
	return 0;
}

sub Paused {
	my $self=shift;
	return $$self{'Paused'};
}

sub Aborted {
	my $self=shift;
	return $$self{'Aborted'};
}

sub Ran {
	my $self=shift;
	return $$self{'Ran'};
}

sub Resumed {
	my $self=shift();
	my $val=shift();
	if (!defined($val)){
		return $$self{'Resumed'};
	} else {
		$$self{'Resumed'}=1;
		return 1;
	}
}

sub PreviousScan {
	my $self=shift();
	my $val=shift();
	if (!defined($val)){
		return $$self{'PreviousScan'};
	} else {
		$$self{'PreviousScan'}=1;
		return 1;
	}
}

sub Pause {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if ($self->SetStatValue($StatusFile,"status","paused")){
		$$self{'Paused'}=1;
		return 1;
	}
	return 0;
}

sub Abort {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	$$self{'Aborted'}=1;
	return 1;
}

sub Running {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if ($self->SetStatValue($StatusFile,"status","running")){
		$$self{'Ran'}=1;
		return 1;
	}
	return 0;
}

sub ServiceDiscoveryComplete {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	$$self{'ServiceDiscoveryComplete'}=1;
	if ($self->SetStatValue($StatusFile,"status","servicediscoverycomplete")){
		return 1;
	}
	return 0;
}

sub isServiceDiscoveryComplete {
	my $self=shift;
	return $$self{'ServiceDiscoveryComplete'};
}

sub Finished {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if ($self->SetStatValue($StatusFile,"status","finished")){
		return 1;
	}
	return 0;
}

sub GetStatus {
	my $self=shift;
	my $StatusFile=$self->StatusFile;
	if (my $status = $self->GetStatValue($StatusFile,"status")){
		return $status;
	}
	return 0;
}

sub ScanningTarget {
	my $self=shift();
	my $target=shift();
	my $file=$$self{'ResultsDirectory'} . "/${target}/.scanning";
	if ((! -f "$file") && (open(ST,">$file"))){
		close ST;
		return 1;
	} 
	return 0;
}

sub NotScanningTarget {
	my $self=shift();
	my $target=shift();
	my $file=$$self{'ResultsDirectory'} . "/${target}/.scanning";
	if (unlink($file)){
		return 1;
	}
	return 0;
}

sub TargetBeingScanned {
	my $self=shift();
	my $target=shift();
	my $file=$$self{'ResultsDirectory'} . "/${target}/.scanning";
	if (-f "$file"){
		return 1;
	}
	return 0;
}

# Process Control

sub MaxThreads {
	my $self=shift();
	my $num=shift();
	if (!$num || $num =~ /\D/){
		return $$self{'MaxThreads'};
	} else {
		$$self{'MaxThreads'}=$num;
		return 1;
	}
}

sub isShellSafe {
	my $string=shift();
	return 0 if ($string =~ /[|\(\)\*\"\'\;\&\$\@\~`><]/);
	return 1;
}

sub shellEscape {
	my $self=shift();
	my $cmd=shift();
	my @elements = split ("\\s", $cmd);
	$cmd=shift(@elements);
	for my $el (@elements){
		if ($el =~ ">"){
			$cmd .= " $el";
		} else {
			$cmd .= " \"$el\"";
		}
	}
	return $cmd;
}

sub Backticks {
	my $self=shift();
	my $Log=$$self{'Log'};
	my $cmd=shift();
	my $quiet=shift();
	my @results;
	if ($cmd){
		#$cmd=$self->shellEscape("$cmd")
		$Log->Exec ("Executing: $cmd") if (!$quiet);
		@results=`$cmd`;
		my $rc=$?; $rc = $rc >> 8;
		return $rc,@results;
	}
	return undef;
}

sub CPUs {
	my $self=shift();
	return $$self{'CPUs'};
}

sub loadAverage {
	my $self=shift();
	my (%load,$junk);
	if (open(PROC,"/proc/loadavg")){
		my $la=<PROC>;
		close PROC;
		($load{'1'},$load{'5'},$load{'15'},$junk)=split (" ", $la, 4);
	} else {
		return undef;
	}
	# Normalise for CPUs or cores
	$load{'CPUs'}=$$self{'CPUs'};
	for my $i (1,5,15){
		$load{$i}=($load{$i} * 100)/$load{'CPUs'};
	}
	return %load;
}

sub TimedBackticks {
	my $self=shift();
	my $timeOut=shift();
	my $command=shift();
	my $quiet=shift();
	my @results;
	if ($command){
		$SIG{'ALRM'}=sub {
			die ("TIMEOUT");
		};
		my $error=99;
		$$self{'Log'}->Exec ("Timed execution ($timeOut) secs: $command") if (!$quiet);
		alarm ($timeOut);
		eval {
			@results=`$command`;
			$error=$?;
			alarm 0;
		};
		if ("$@" !~ /^TIMEOUT/){
			$SIG{'ALRM'}='';
			$error = $error >> 8;
			return $error, @results;
		} else {
			$SIG{'ALRM'}='';
			$$self{'Log'}->Warn ("Command timed out after $timeOut secs: $command","LOGONLY");
			return 99;
		}
		return $error;
	}
	return undef;
}

sub System {
	my $self=shift();
	my $Log=$$self{'Log'};
	my $cmd=shift();
	my $quiet=shift();
	if ($cmd){
		#$cmd=$self->shellEscape("$cmd")
		$Log->Exec ("Executing: $cmd") if (!$quiet);
		my $error=system("$cmd");
		$error = $error >> 8;
		return $error;
	}
	return undef;
}

sub TimedSystem {
	my $self=shift();
	my $timeOut=shift();
	my $command=shift();
	my $quiet=shift();
	if ($command){
		$SIG{'ALRM'}=sub {
			die ("TIMEOUT");
		};
		my $error=99;
		$$self{'Log'}->Exec ("Timed execution ($timeOut) secs: $command") if (!$quiet);
		alarm ($timeOut);
		eval {
			$error=system("$command");
			alarm 0;
		};

		if ("$@" !~ /^TIMEOUT/){
			$SIG{'ALRM'}='';
			$error = $error >> 8;
			return $error;
		} else {
			$SIG{'ALRM'}='';
			$$self{'Log'}->Warn ("Command timed out after $timeOut secs: $command","LOGONLY");
			# Try to kill the process (in case it is using all the CPU time)
			$SIG{'CHLD'}=sub {
				# Don't want zombie processes hanging around
				my $child=1;
				do {
					$child= waitpid(-1, WNOHANG);
				} while $child>0;
			};
			my $pid=_findpid($command);
			$$self{'Log'}->Warn("$$ - Killing runaway process $pid (exceeded $timeOut secs) ($command)\n");
			kill 15, $pid;
			$SIG{'CHLD'}='';

			sub _findpid {
				my $command=shift();
				my $junk;
				if (index($command,"cd")==0){
					($junk,$command)=split " && ", $command;
				}
				$command=_toDelimit($command,">");
				#print "Finding the process ID of \"$command\"\n";
				my @pids;
				for my $line (`/bin/ps a`){
					if (index($line,"$command") > 1){
						my $pid=$line; $pid =~ s/^[\s]+(\d+)\s[\s\S]+$/$1/g;
						$pid = _toDelimit($pid);
						push @pids, $pid;
						#print "LINE $line ($pid)\n";
					}
				}
				my $pid=pop(@pids);
				#print "Using PID $pid\n";
				return $pid;

				sub _toDelimit {
					my $string=shift();
					my $delimit=shift();
					$delimit = " " if (!$delimit);
					return $string if (index($string,$delimit) < 0);
					$string=substr($string,0,(index($string,"$delimit")-1));
					$string=~s/[\s]+$//;
					return $string;
				}
			}
			return 99;
		}
		return $error;
	}
	return undef;
}

sub TimedSystemRandomKill {
	my $self=shift();
	my $timeOut=shift();
	my $command=shift();
	my $quiet=shift();
	if ($command){
		$SIG{'ALRM'}=sub {
			die ("TIMEOUT");
		};
		my $error;
		eval {
			$$self{'Log'}->Exec ("Timed execution ($timeOut) secs: $command") if (!$quiet);
			alarm ($timeOut);
			$error=system("$command");
			alarm 0;
		};

		if ("$@" !~ /^TIMEOUT/){
			$SIG{'ALRM'}='';
			$error = $error >> 8;
			return $error;
		} else {
			$$self{'Log'}->Warn ("Command timed out after $timeOut secs: $command","LOGONLY");
			# Try to kill the process (in case it is using all the CPU time)
			my ($junk,$baseCommand,$bin);
			if (index($command,"cd")==0){
				($junk,$baseCommand)=split " && ", $command; $bin = _toSpace($baseCommand);
			} else {
				$baseCommand = $command;
				$bin=_toSpace($command);
			}
			my @proc=`ps a | grep "$baseCommand"`;
			for my $_proc (@proc){
				$_proc =~ s/^(\d+)[\s\S]{1,}$/$1/;
				next if (!$_proc || $_proc !~ /\d+/);
				next if ($_proc =~ /\D/);
				if (-f "/proc/$_proc/cmdline"){
					if (open(PROC,"/proc/$_proc/cmdline")){
						my $_cmdline=<PROC>;
						close PROC;
						$baseCommand = _toSpace($baseCommand,">");
						if (index($_cmdline,$baseCommand)>=0){
							$$self{'Log'}->Warn("PID $$ KILLING runaway process PID $_proc ($baseCommand)\n");
							kill 15, $_proc;
						}
					}
				}
			}

			sub _toSpace {
				my $string=shift();
				my $delimit = shift();
				$delimit=" " if (!$delimit);
				if (index($string,"$delimit") < 0){
					return $string;
				}
				return substr($string,0,index($string,"$delimit"));
			}

			$SIG{'ALRM'}='';
			return 99;
		}
		return $error;
	}
	return undef;
}

#*********************
# Issues Handling

sub AddSDMIssue {
	my $self=shift();
	my $issue=shift();
	if ($issue =~ /^\s/){
		$issue =~ s/^\s+//g;
	}
	if (($issue =~ /^\#/) || ($issue !~ /\w/) || ($issue !~ /\*/)) {
		return 0;
	}
	chomp $issue;
	if ($issue =~ /^NEETSDMISSUE\*/){
		$issue =~ s/NEETSDMISSUE\*//;
		push @{$$self{'SDMIssues'}}, "$issue";
	} else {
		push @{$$self{'SDMIssueTriggers'}}, "$issue";
	}
	return 1;
}

sub PrintSDMIssues {
	my $self=shift();
	for my $i (@{$$self{'SDMIssues'}}){
		print "$i\n";
	}
	for my $i (@{$$self{'SDMIssueTriggers'}}){
		print "$i\n";
	}
}

sub GetSDMIssue {
	my $self=shift();
	my $svc=shift();
	my $banner=shift();
	for my $t (@{$$self{'SDMIssueTriggers'}}){
		my ($s,$b,$r) = split ("\\*", $t);
		if ($svc eq $s){
			if ($b){
				if ($banner && ($banner =~ /$b/)){
					for my $i (@{$$self{'SDMIssues'}}){
						if (defined($i) && ($i =~ /\S/) && ($i =~ /^SDM$r\*/)){
							# return ref,level,text
							return split ("\\*", $i);
						}
					}
				}
			} else {
					for my $i (@{$$self{'SDMIssues'}}){
						if ($i =~ /^$r\*/){
							# return ref,level,text
							return split ("\\*", $i);
						}
					}
			}
			last;
		}		
	}
	return undef;
}

#*********************

sub RecordIssue {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/issues.txt";
	my $target=shift();
	my ($host,$junk) = split (":", $target);
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	my $outputDir=$$self{'ResultsDirectory'} . "/$host/";
	close FH if (open(FH,">$outputDir/.issue"));
	$$self{'Log'}->Issue("$target -> $text");
	$self->SetListItem("$EventFile","$target\t[$label]\t$text");
	$self->SetListItem("$$self{'MasterIssuesFile'}","$target\tIssue\t[$label]\t$text");
	return 0;
}

sub RecordVulnerability {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/vulnerabilities.txt";
	my $target=shift();
	my ($host,$junk) = split (":", $target);
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	my $outputDir=$$self{'ResultsDirectory'} . "/$host/";
	close FH if (open(FH,">$outputDir/.vuln"));
	$$self{'Log'}->Vuln("$target -> $text");
	$self->SetListItem("$EventFile","$target\t[$label]\t$text");
	$self->SetListItem($$self{'MasterIssuesFile'},"$target\tVuln\t[$label]\t$text");
	return 0;
}

sub RecordCompromise {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/compromises.txt";
	my $target=shift();
	my ($host,$junk) = split (":", $target);
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	my $outputDir=$$self{'ResultsDirectory'} . "/$host/";
	close FH if (open(FH,">$outputDir/.comp"));
	$$self{'Log'}->Comp("$target -> $text");
	$self->SetListItem("$EventFile","$target\t[$label]\t$text");
	$self->SetListItem("$$self{'MasterIssuesFile'}","$target\tComp\t[$label]\t$text");
	return 0;
}

sub StoreGuessedPassword {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/guessedPasswords.txt";
	my $target=shift();
	my $level=shift();
	my ($host,$junk) = split (":", $target);
	my $service=shift();
	my $username=shift();
	my $password=shift();
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	$text="Guessed Password: $text";
	$self->SetListItem("$EventFile","$target\t$service\t$username\t$password");
	if ($level eq "issue"){
		$self->RecordIssue($target, $label, $text);
	} elsif ($level eq "vuln"){
		$self->RecordVulnerability($target, $label, $text);
	} elsif ($level eq "comp"){
		$self->RecordCompromise($target, $label, $text);
	}
	return 0;
}

sub MissingPatch {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/missingPatches.txt";
	my $target=shift();
	my $level=shift();
	my ($host,$junk) = split (":", $target);
	my $service=shift();
	my $patch=shift();
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	$text="Missing Patch: $text";
	$self->SetListItem("$EventFile","$target\t$service\t$patch");
	if ($level eq "issue"){
		$self->RecordIssue($target, $label, $text);
	} elsif ($level eq "vuln"){
		$self->RecordVulnerability($target, $label, $text);
	} elsif ($level eq "comp"){
		$self->RecordCompromise($target, $label, $text);
	}
	return 0;
}

sub ConfigError {
	my $self=shift();
	my $EventFile=$$self{'ResultsDirectory'} . "/configurationErrors.txt";
	my $target=shift();
	my $level=shift();
	my ($host,$junk) = split (":", $target);
	my $label=shift();
	my $text=shift();
	return 1 if (!$text);
	chomp $text;
	$text="Configuration Error: $text";
	$self->SetListItem("$EventFile","$target\t$label\t$text");
	if ($level eq "issue"){
		$self->RecordIssue($target, $label, $text);
	} elsif ($level eq "vuln"){
		$self->RecordVulnerability($target, $label, $text);
	} elsif ($level eq "comp"){
		$self->RecordCompromise($target, $label, $text);
	}
	return 0;
}

#*********************
# Status File Handling
use Fcntl ':flock';

sub ReadFile {
	# Reads $file into an array
	my $self=shift();
	my $file=shift();
	my $FH;
	if (-f $file && open($FH,$file)){
		flock($FH,LOCK_EX);
		my @FILE=<$FH>;
		flock($FH,LOCK_UN);
		close $FH;
		return @FILE;
	}
	return undef;
}

sub GetStatValue {
	# Matches first key in file and gets the value (space-separated)
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	my @FILE=$self->ReadFile($file);
	for my $f (@FILE){
		if ($f && index($f,"$key ")==0){
			my ($key,$val)=split (" ", $f, 2);
			return undef if (!defined($val));
			chomp $val;
			return $val;
		}
	}
	return undef;
}

sub GetStatKey {
	# Returns 1 if key exists in $file, 0 otherwise
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	my @FILE=$self->ReadFile($file);
	for my $f (@FILE){
#		if (defined($f) && $f =~ /^$key\s/){
		if (defined($f) && ((index($f,"$key ")==0) || (index($f,"$key\n")==0))){
			return 1;
		}
	}
	return 0;
}

sub GetStatKeys {
	# Returns an array of keys in $file
	my $self=shift();
	my $file=shift();
	my @FILE=$self->ReadFile($file);
	my @keys;
	for my $f (@FILE){
		if ($f && ($f =~ /^\S/) && ($f !~ /^#/)){
			my $key = substr($f,0,index($f," "));
			push @keys, $key;
		}
	}
	return @keys;
}

sub SetStatKey {
	# Sets $key in $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if (!$self->GetStatKey($file,$key)){
		if (open($FH,">>$file")){
			flock($FH,LOCK_EX);
			print $FH "$key \n";
			flock($FH,LOCK_UN);
			close $FH;
			return 1;
		}
	}
	return 0;
}

sub DelStatKey {
	# Removes $key from $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if ($self->GetStatKey($file,$key)){
		my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
		if (open($FH,$file)){
			flock($FH,LOCK_EX);
			$locked=1;
			@FILE=<$FH>;
		}

		for my $line (@FILE){
			if ($line && ((index($line,"$key ")==0) || (index($line,"$key\n")==0)) ) {
				$matched=1;
				next;
			}
			push @NEW, $line if ($line);
		}
		$#FILE=-1;

		if ($locked && $matched && open($FH,">$file")){
			print $FH @NEW;
			flock($FH,LOCK_UN);
			close $FH;
			$locked=0;
			$#NEW=-1;
			return 1;
		}
		if ($locked){
			flock($FH,LOCK_UN);
			close $FH;
		}
		$#NEW=-1;
	}
	return 0;
}

sub SetStatValue {
	# Sets $key=$value in $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;

	my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
	if (open($FH,$file)){
		flock($FH,LOCK_EX);
		$locked=1;
		@FILE=<$FH>;
	}

	for my $pair (@FILE){
		if ($pair && index($pair,"$key ")==0){
			$matched=1;
			push @NEW, "$key $value\n";
			next;
		}
		push @NEW, $pair if ($pair);
	}
	$#FILE=-1;

	if (!$matched){
		push @NEW, "$key $value\n";			
	}

	if (open($FH,">$file")){
		flock($FH,LOCK_EX) if (!$locked);
		print $FH @NEW;
		flock($FH,LOCK_UN);
		close $FH;
		$locked=0;
		$#NEW=-1;
		return 1;
	}
	if ($locked){
		flock($FH,LOCK_UN);
		close $FH;
	}
	$#NEW=-1;
	return 0;
}

sub AppendStatValue {
	# Appends "$key $value" to $file, even it if already exists
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;
	my $FH;
	if (open($FH,">>$file")){
		flock($FH,LOCK_EX);
		print $FH "$key $value\n";
		flock($FH,LOCK_UN);
		close $FH;
		return 1;
	}
	return 0;
}

sub DelStatKeyValue {
	# Removes "$key $value" from $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;

	if ($self->GetStatValue($file,$key) eq $value){
		my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
		if (open($FH,$file)){
			flock($FH,LOCK_EX);
			$locked=1;
			@FILE=<$FH>;
		}

		for my $pair (@FILE){
			if ($pair && index($pair,"$key $value")==0){
				$matched=1;
				next;
			}
			push @NEW, $pair if ($pair);
		}
		$#FILE=-1;

		if ($locked && $matched && open($FH,">$file")){
			print $FH @NEW;
			flock($FH,LOCK_UN);
			close $FH;
			$locked=0;
			$#NEW=-1;
			return 1;
		}
		if ($locked){
			flock($FH,LOCK_UN);
			close $FH;
		}
		$#NEW=-1;

	}
	return 0;

}

# For lists of keys without values, such as LiveHosts list.
# SetListItem will not allow duplicate entries, AND it doesn't
# put a space on the end of each line.

sub SetListItem {
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if (!$self->GetStatKey($file,$key)){
		my $FH;
		if (open($FH,">>$file")){
			flock($FH,LOCK_EX);
			print $FH "$key\n";
			flock($FH,LOCK_UN);
			close $FH;
			return 1;
		}
	}
	return 0;
}

# For keeping loose track of the number of hosts which have finished the Service Discovery Phase

sub SetHostFinished {
  my $self=shift();
	my $FH;
	if (open($FH,">>$$self{'CompletedFile'}")){
		flock($FH,LOCK_EX);
    print $FH "1";
		flock($FH,LOCK_UN);
		close $FH;
  }
}

sub NumHostsFinished {
  my $self=shift();
  return (-s $$self{'CompletedFile'});
}

1;
