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

package JR::Parsers::Nmap;

# Oritinal Author: Anthony G Persaud

# MODIFIED For Neet by JR - UDP which are "open" are NOT the same as "open|filtered".
# Added a switch to select whether udp_open_ports() returns ports which are "open|filtered" or just "open".

use strict;
use XML::Twig;
use Storable qw(dclone);
use vars qw($VERSION %D);

$VERSION = 1.13;

sub new {

my ($class,$self) = shift;
    $class        = ref($class) || $class;

%{$self->{HOSTS}}   = %{$self->{SESSION}} = ();

$self->{twig}     = new XML::Twig(
	start_tag_handlers 	=>
		{nmaprun => \&_nmaprun_start_tag_hdlr },
		
	twig_roots 		=> {
		scaninfo => \&_scaninfo_tag_hdlr,
		finished => \&_finished_tag_hdlr,
		host 	 => \&_host_tag_hdlr
				},
	ignore_elts 	=> {
		addport 	=> 1,
		debugging	=> 1,
		verbose		=> 1,
		hosts		=> 1,
                taskbegin       => 1,
                taskend         => 1,
                taskprogress    => 1
		}

		);

bless ($self,$class);
return $self;
}


#/*****************************************************************************/
# NMAP::PARSER OBJECT METHODS
#/*****************************************************************************/

#Safe parse and parsefile will return $@ which will contain the error
#that occured if the parsing failed (it might be empty when no error occurred)
sub _init {
	my $self = shift;
	$D{callback} = $self->{callback};
}

sub _clean {
	my $self = shift;
	$self->{SESSION} = dclone($D{$$}{SESSION}) if($D{$$}{SESSION});
	$self->{HOSTS}   = dclone($D{$$}{HOSTS}  ) if($D{$$}{HOSTS}  );
	delete $D{$$};
	delete $D{callback};
}

sub callback {
	my $self = shift;
	my $callback = shift; #first arg is CODE
	if(ref($callback) eq 'CODE'){
		$self->{callback}{coderef} = $callback;
		$self->{callback}{is_registered} = 1;
	} else {
		$self->{callback}{is_registered} = 0;
	}
	
	#returns if a callback is registered or not
	return $self->{callback}{is_registered};
}

sub parse {
	my $self = shift;
	$self->_init();
	$self->{twig}->safe_parse(@_);
	if($@){die $@;}
	$self->_clean();
	$self->purge;
	return $self;
}

sub parsefile {
	my $self = shift;
	$self->_init();
	$self->{twig}->safe_parsefile(@_);
	if($@){die $@;}
	$self->_clean();
	$self->purge;
	return $self;
}

sub parsescan {
	my $self = shift;
	my $nmap = shift;
	my $args = shift;
	my @ips = @_;
	my $FH;

	if($args =~ /-o(?:X|N|G)/){
		die "[Nmap-Parser] Cannot pass option '-oX', '-oN' or '-oG' to parsecan()";
	}
	
	my $cmd = "$nmap $args -v -v -v -oX - ".(join ' ',@ips);
	open $FH, "$cmd |" || die "[Nmap-Parser] Could not perform nmap scan - $!";
	$self->_init();
	$self->parse($FH);
	close $FH;
	$self->_clean();
	$self->purge;
	return $self;
	
}


sub purge {
	my $self = shift;
	$self->{twig}->purge;
	return $self;
}

sub ipv4_sort {
	my $self = shift;
	
	return (sort {
		my @ipa = split('\.',$a);
		my @ipb = split('\.',$b);
			$ipa[0] <=> $ipb[0] ||
			$ipa[1] <=> $ipb[1] ||
			$ipa[2] <=> $ipb[2] ||
			$ipa[3] <=> $ipb[3]
		} @_);
}


#MAIN SCAN INFORMATION
sub get_session {
	my $self = shift;
	my $obj = JR::Parsers::Nmap::Session->new($self->{SESSION});
	return $obj;
}

#HOST STUFF
sub get_host {
	my ($self,$ip) = (@_);
	if($ip eq ''){
		warn "[Nmap-Parser] No IP address given to get_host()\n";return undef;
	}
	$self->{HOSTS}{$ip};	
}

sub del_host {
	my ($self,$ip) = (@_);
	if($ip eq ''){
		warn "[Nmap-Parser] No IP address given to del_host()\n";
		return undef;
	}
	delete $self->{HOSTS}{$ip};
}

sub all_hosts {
	my $self = shift;
	my $status = shift || '';
	
	return (values %{$self->{HOSTS}}) if($status eq '');
	
	my @hosts = grep {$_->{status} eq $status} (values %{$self->{HOSTS}});
	return @hosts;
}

sub get_ips {
	my $self = shift;
	my $status = shift || '';
	
	return $self->ipv4_sort(keys %{$self->{HOSTS}}) if($status eq '');
	
	my @hosts = grep {$self->{HOSTS}{$_}{status} eq $status} (keys %{$self->{HOSTS}});
	return $self->ipv4_sort(@hosts);
	
}


#/*****************************************************************************/
# PARSING TAG HANDLERS FOR XML::TWIG
#/*****************************************************************************/

sub _nmaprun_start_tag_hdlr {

	my ($twig, $tag) = @_;
	
$D{$$}{SESSION}{start_time}  = $tag->{att}->{start};
$D{$$}{SESSION}{nmap_version}= $tag->{att}->{version};
$D{$$}{SESSION}{start_str}   = $tag->{att}->{startstr};
$D{$$}{SESSION}{xml_version} = $tag->{att}->{xmloutputversion};
$D{$$}{SESSION}{scan_args}   = $tag->{att}->{args};
$D{$$}{SESSION}              = JR::Parsers::Nmap::Session->new($D{$$}{SESSION});

$twig->purge;	

}

sub _scaninfo_tag_hdlr {
	my ($twig, $tag) = @_;
	my $type        = $tag->{att}->{type};
        my $proto       = $tag->{att}->{protocol};
	my $numservices = $tag->{att}->{numservices};
	
	if(defined($type)){ #there can be more than one type in one scan
		$D{$$}{SESSION}{type}{$type}        = $proto;
		$D{$$}{SESSION}{numservices}{$type} = $numservices;
	}
	$twig->purge;
}



sub _finished_tag_hdlr {
	my ($twig, $tag) = @_;
	$D{$$}{SESSION}{finish_time} = $tag->{att}->{time};
	$D{$$}{SESSION}{time_str}     = $tag->{att}->{timestr};
	$twig->purge;
}



#parses all the host information in one swoop (calling __host_*_tag_hdlrs)
sub _host_tag_hdlr {
	my ($twig,$tag) = @_;
	my $id = undef;
	
	return undef unless(defined $tag);
	#GET ADDRESS INFO
	my $addr_hashref;
	$addr_hashref = __host_addr_tag_hdlr($tag);
	#use this as the identifier
	$id           = $addr_hashref->{ipv4} ||
			$addr_hashref->{ipv6} ||
			$addr_hashref->{mac}; #worstcase use MAC
	
	$D{$$}{HOSTS}{$id}{addrs} = $addr_hashref;
	
	return undef unless(defined($id) || $id ne '');
	
	#GET HOSTNAMES
	$D{$$}{HOSTS}{$id}{hostnames} = __host_hostnames_tag_hdlr($tag);
	
	#GET STATUS
	$D{$$}{HOSTS}{$id}{status} = $tag->first_child('status')->{att}->{state};
	$D{$$}{HOSTS}{$id}{reason} = $tag->first_child('status')->{att}->{reason};
    
	#CONTINUE PROCESSING IF STATUS IS UP - OTHERWISE NO MORE XML
	if(lc($D{$$}{HOSTS}{$id}{status}) eq 'up'){
	
	    $D{$$}{HOSTS}{$id}{ports}         = __host_port_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{os}            = __host_os_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{uptime}        = __host_uptime_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{tcpsequence}   = __host_tcpsequence_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{ipidsequence}  = __host_ipidsequence_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{tcptssequence} = __host_tcptssequence_tag_hdlr($tag);
	    $D{$$}{HOSTS}{$id}{distance}      = __host_distance_tag_hdlr($tag); #returns simple value
	    
	    
	
	}	
	#CREATE HOST OBJECT FOR USER
	$D{$$}{HOSTS}{$id} = JR::Parsers::Nmap::Host->new($D{$$}{HOSTS}{$id});
	
	if($D{callback}{is_registered}){
		&{$D{callback}{coderef}}($D{$$}{HOSTS}{$id});
		delete $D{$$}{HOSTS}{$id};
	}

	$twig->purge;
    
}







sub __host_addr_tag_hdlr {
	my $tag = shift;
	my $addr_hashref;
	#children() will return all children with tag name address
	for my $addr ($tag->children('address')){
		if(lc($addr->{att}->{addrtype}) eq 'mac')
		{
			#we'll assume for now, only 1 MAC address per system
			$addr_hashref->{mac}{addr} = $addr->{att}->{addr};
			$addr_hashref->{mac}{vendor} = $addr->{att}->{vendor};
		}
		elsif(lc($addr->{att}->{addrtype}) eq 'ipv4') {
			$addr_hashref->{ipv4} = $addr->{att}->{addr};
		} #support for ipv6? we'll see
		elsif(lc($addr->{att}->{addrtype}) eq 'ipv6') {
			$addr_hashref->{ipv6} = $addr->{att}->{addr};
		}

	}

	return $addr_hashref;
	}



sub __host_hostnames_tag_hdlr {
	my $tag = shift;
	
	my $hostnames_tag = $tag->first_child('hostnames');
	return undef unless(defined $hostnames_tag);
	
	my @hostnames;
	
	for my $name ($hostnames_tag->children('hostname'))
	{
		push @hostnames, $name->{att}->{name};
	}
	
	return \@hostnames;

}


sub __host_port_tag_hdlr {
	my $tag = shift;
	my ($port_hashref,$ports_tag);
	
	$ports_tag = $tag->first_child('ports');
	
	return undef unless(defined $ports_tag);
	
	#Parsing Extraports
	my $extraports_tag = $ports_tag->first_child('extraports');
	if(defined $extraports_tag && $extraports_tag ne ''){
		$port_hashref->{extraports}{state} = $extraports_tag->{att}->{state};
		$port_hashref->{extraports}{count} = $extraports_tag->{att}->{count};
	}
	
	#Parsing regular port information
	
	my ($tcp_port_count, $udp_port_count) = (0,0);
	
	for my $port_tag ($ports_tag->children('port')){
		my $proto  = $port_tag->{att}->{protocol};
		my $portid = $port_tag->{att}->{portid};
		my $state  = $port_tag->first_child('state');
		my $owner  = $port_tag->first_child('owner') || undef;
		
		$tcp_port_count++ if($proto eq 'tcp');
		$udp_port_count++ if($proto eq 'udp');
		
		$port_hashref->{$proto}{$portid}{state} = $state->{att}->{state} || 'unknown' 
			if($state ne '');
		
		#GET SERVICE INFORMATION
		$port_hashref->{$proto}{$portid}{service}        = __host_service_tag_hdlr($port_tag,$portid)
			if(defined($proto) && defined($portid));
		
		#GET OWNER INFORMATION
		$port_hashref->{$proto}{$portid}{service}{owner} = $owner->{att}->{name}
			if(defined($owner));
			
		#These are added at the end, otherwise __host_service_tag_hdlr will overwrite
		#GET PORT STATE
		
		
				
	}
	
	$port_hashref->{tcp_port_count} = $tcp_port_count;
	$port_hashref->{udp_port_count} = $udp_port_count;
	
	return $port_hashref;
	
	
}


sub __host_service_tag_hdlr {
	my $tag = shift;
	my $portid = shift; #need a way to remember what port this service runs on
	my $service = $tag->first_child('service[@name]');
	my $service_hashref;
	$service_hashref->{port}       = $portid;
	
	if(defined $service){
	$service_hashref->{name}       = $service->{att}->{name}  || 'unknown';
	$service_hashref->{version}    = $service->{att}->{version};
	$service_hashref->{product}    = $service->{att}->{product};
	$service_hashref->{extrainfo}  = $service->{att}->{extrainfo};
	$service_hashref->{proto}      = $service->{att}->{proto} || $service->{att}->{protocol} || 'unknown';
	$service_hashref->{rpcnum}     = $service->{att}->{rpcnum};
	$service_hashref->{tunnel}     = $service->{att}->{tunnel};
	$service_hashref->{method}     = $service->{att}->{method};
	$service_hashref->{confidence} = $service->{att}->{conf};
	$service_hashref->{fingerprint} = $service->{att}->{servicefp};
	}

	return $service_hashref;
}


sub __host_os_tag_hdlr {
	my $tag = shift;
	my $os_tag = $tag->first_child('os');
	my $os_hashref;
	my $portused_tag;
	my $os_fingerprint;
	
	if(defined $os_tag){
	#get the open port used to match os
	$portused_tag = $os_tag->first_child("portused[\@state='open']"); 
	$os_hashref->{portused}{open} = $portused_tag->{att}->{portid}   if(defined $portused_tag);
	
	#get the closed port used to match os
	$portused_tag = $os_tag->first_child("portused[\@state='closed']");
	$os_hashref->{portused}{closed} = $portused_tag->{att}->{portid} if(defined $portused_tag);
	
	#os fingerprint
        $os_fingerprint = $os_tag->first_child("osfingerprint");
        $os_hashref->{os_fingerprint} = $os_fingerprint->{'att'}->{'fingerprint'} if(defined $os_fingerprint);

	#This will go in JR::Parsers::Nmap::Host::OS
	my $osmatch_index = 0;
	for my $osmatch ($os_tag->children('osmatch')){
		$os_hashref->{osmatch_name}   [$osmatch_index] = $osmatch->{att}->{name};
		$os_hashref->{osmatch_name_accuracy}[$osmatch_index] = $osmatch->{att}->{accuracy};
		$osmatch_index++;
		}
	$os_hashref->{'osmatch_count'} = $osmatch_index;
	
	#parse osclass tags
	my $osclass_index = 0;
        for my $osclass ($os_tag->children('osclass')){
		$os_hashref->{osclass_osfamily}[$osclass_index] = $osclass->{att}->{osfamily};
		$os_hashref->{osclass_osgen}   [$osclass_index] = $osclass->{att}->{osgen};
		$os_hashref->{osclass_vendor}  [$osclass_index] = $osclass->{att}->{vendor};
		$os_hashref->{osclass_type}    [$osclass_index] = $osclass->{att}->{type};
		$os_hashref->{osclass_class_accuracy}[$osclass_index] = $osclass->{att}->{accuracy};
		$osclass_index++;		
	}
	$os_hashref->{'osclass_count'} = $osclass_index;
	}
	

	return $os_hashref;	
	
}

sub __host_uptime_tag_hdlr {
	my $tag = shift;
	my $uptime = $tag->first_child('uptime');
	my $uptime_hashref;
	
	if(defined $uptime){
		$uptime_hashref->{seconds}  = $uptime->{att}->{seconds};
		$uptime_hashref->{lastboot} = $uptime->{att}->{lastboot};
		
	}
	
	return $uptime_hashref;
	
}


sub __host_tcpsequence_tag_hdlr {
	my $tag = shift;
	my $sequence = $tag->first_child('tcpsequence');
	my $sequence_hashref;
	return undef unless($sequence);
	$sequence_hashref->{class} = $sequence->{att}->{class};
	$sequence_hashref->{values} = $sequence->{att}->{values};
	$sequence_hashref->{index} = $sequence->{att}->{index};
	
	return $sequence_hashref;
	
	}


sub __host_ipidsequence_tag_hdlr {
	my $tag = shift;
	my $sequence = $tag->first_child('ipidsequence');
	my $sequence_hashref;
	return undef unless($sequence);
	$sequence_hashref->{class} = $sequence->{att}->{class};
	$sequence_hashref->{values} = $sequence->{att}->{values};
	return $sequence_hashref;
	
	}


sub __host_tcptssequence_tag_hdlr {
	my $tag = shift;
	my $sequence = $tag->first_child('tcptssequence');
	my $sequence_hashref;
	return undef unless($sequence);
	$sequence_hashref->{class} = $sequence->{att}->{class};
	$sequence_hashref->{values} = $sequence->{att}->{values};
	return $sequence_hashref;
	}

sub __host_distance_tag_hdlr {
	my $tag = shift;
	my $distance = $tag->first_child('distance');
	return undef unless($distance);
	return $distance->{att}->{value};
}



#/*****************************************************************************/
# NMAP::PARSER::SESSION
#/*****************************************************************************/

package JR::Parsers::Nmap::Session;
use vars qw($AUTOLOAD);

sub new {
	my $class = shift;
	$class    = ref($class) || $class;
	my $self  =  shift      || {};
	bless ($self,$class);
	return $self;
}

#Support for:
#start_time, start_str, finish_time, time_str, nmap_version, xml_version, scan_args
sub AUTOLOAD {
	(my $param = $AUTOLOAD) =~ s{.*::}{}xms;
	return if($param eq 'DESTROY');
	no strict 'refs';
	*$AUTOLOAD = sub {return $_[0]->{lc $param}};	
	goto &$AUTOLOAD;
}


sub numservices {
	my $self = shift;
	my $type = shift || ''; #(syn|ack|bounce|connect|null|xmas|window|maimon|fin|udp|ipproto)

	return unless(ref($self->{numservices}) eq 'HASH');

	if($type ne ''){return $self->{numservices}{$type};}
	else {
		my $total = 0;
		for (values %{$self->{numservices}}){$total +=$_;}
		return $total;
	}#(else) total number of services together
}


sub scan_types 		{return sort {$a cmp $b} (keys %{$_[0]->{type}}) if(ref($_[0]->{type}) eq 'HASH');}
sub scan_type_proto 	{return $_[1] ? $_[0]->{type}{$_[1]} : undef;}



#/*****************************************************************************/
# NMAP::PARSER::HOST
#/*****************************************************************************/

package JR::Parsers::Nmap::Host;
use vars qw($AUTOLOAD);

sub new {
my $class = shift;
$class    = ref($class) || $class;
my $self  =  shift      || {};
$$self{strictUDPOpens}=0;

bless ($self,$class);
return $self;
}

sub strictUDPOpens {
	my $self = shift;
	$$self{strictUDPOpens}=1;
	return $self;
}
sub noStrictUDPOpens {
	my $self = shift;
	$$self{strictUDPOpens}=0;
	return $self;
}


sub status {return $_[0]->{status};}
sub reason {return $_[0]->{reason};}

sub addr {my $default =  $_[0]->{addrs}{ipv4} || $_[0]->{addrs}{ipv6}; return $default;}
sub addrtype {
	if($_[0]->{addrs}{ipv4}){return 'ipv4';}
	elsif($_[0]->{addrs}{ipv6}){return 'ipv6';}
	}

sub ipv4_addr {return $_[0]->{addrs}{ipv4};}
sub ipv6_addr {return $_[0]->{addrs}{ipv6};}

sub mac_addr {return $_[0]->{addrs}{mac}{addr};}
sub mac_vendor {return $_[0]->{addrs}{mac}{vendor};}

#returns the first hostname
sub hostname  {
	my $self = shift;
	my $index = shift || 0;
	if(ref($self->{hostnames}) ne 'ARRAY'){return '';}
	if(scalar @{ $self->{hostnames}} <= $index){
	$index = scalar @{ $self->{hostnames}} -1;
	}
	return $self->{hostnames}[$index] if(scalar @{ $self->{hostnames} });
}

sub all_hostnames {return @{$_[0]->{hostnames}};}
sub extraports_state {return $_[0]->{ports}{extraports}{state};}
sub extraports_count {return $_[0]->{ports}{extraports}{count};}
sub distance {return $_[0]->{distance}; }

sub _get_ports {
	my $self = shift;
	my $proto = pop; #param might be empty, so this goes first
	my $state = lc(shift);    #open, filtered, closed or any combination
	my @matched_ports = ();
	
	#if $state eq '', then tcp_ports or udp_ports was called for all ports
	#therefore, only return the keys of all ports found
	if($state eq ''){return sort {$a <=> $b} (keys %{ $self->{ports}{$proto} }) }
	
	#the port parameter can be set to either any of these also 'open|filtered'
	#can count as 'open' and 'filetered'. Therefore I need to use a regex from now on
	#if $param is empty, then all ports match.

	for my $portid (keys %{ $self->{ports}{$proto} }){
		#escape metacharacters ('|', for example in: open|filtered)
		#using \Q and \E

		if ($proto && ("$proto" eq "udp") && $$self{strictUDPOpens}){
			push(@matched_ports, $portid) if($self->{ports}{$proto}{$portid}{state} =~ /^$state$/);
			if ($state eq "filtered"){
				push(@matched_ports, $portid) if($self->{ports}{$proto}{$portid}{state} =~ /$state$/);
			}
		} else {
			push(@matched_ports, $portid) if($self->{ports}{$proto}{$portid}{state} =~ /\Q$state\E/);
		}
	}
	return sort {$a <=> $b} @matched_ports;
	
}

sub _get_port_state {
	my $self = shift;
	my $proto = pop; #portid might be empty, so this goes first
	my $portid = lc(shift);    
	
	return undef unless(exists $self->{ports}{$proto}{$portid});
	return $self->{ports}{$proto}{$portid}{state};
	
	}

#changed this to use _get_ports since it was similar code
sub tcp_ports { return _get_ports(@_,'tcp');}
sub udp_ports { return _get_ports(@_,'udp');}

sub tcp_port_count {return $_[0]->{ports}{tcp_port_count};}
sub udp_port_count {return $_[0]->{ports}{udp_port_count};}

sub tcp_port_state {return _get_port_state(@_,'tcp');}
sub udp_port_state {return _get_port_state(@_,'udp');}

sub tcp_service {
	my $self = shift;
	my $portid = shift;
	if($portid eq ''){
	warn "[Nmap-Parser] No port number passed to tcp_service()\n";	
		return undef;}
	return JR::Parsers::Nmap::Host::Service->new(
			$self->{ports}{tcp}{$portid}{service}
			);
		 }

sub udp_service {
	my $self = shift;
	my $portid = shift;
	if($portid eq ''){
	warn "[Nmap-Parser] No port number passed to udp_service()\n";	
		return undef;}
	return JR::Parsers::Nmap::Host::Service->new(
			$self->{ports}{udp}{$portid}{service}
			);

		 }


#usually the first one is the highest accuracy

sub os_sig {return JR::Parsers::Nmap::Host::OS->new($_[0]->{os});}


#Support for:
#tcpsequence_class, tcpsequence_values, tcpsequence_index,
#ipidsequence_class, ipidsequence_values, tcptssequence_values,
#tcptssequence_class, uptime_seconds, uptime_lastboot
#tcp_open_ports, udp_open_ports, tcp_filtered_ports, udp_filtered_ports,
#tcp_closed_ports, udp_closed_ports
sub AUTOLOAD {
	(my $param = $AUTOLOAD) =~ s{.*::}{}xms;
	return if($param eq 'DESTROY');
	my($type,$val) = split /_/, lc($param);
	#splits the given method name by '_'. This will determine the function and param
	no strict 'refs';
	
	if( ($type eq 'tcp' || $type eq 'udp') && ($val eq 'open' || $val eq 'filtered' || $val eq 'closed') ){
					
		#they must be looking for port info: tcp or udp. The $val is either open|filtered|closed
		*$AUTOLOAD = sub {return _get_ports($_[0], $val, $type);};	
		goto &$AUTOLOAD;
		
	} elsif(defined $type && defined $val) {
		#must be one of the 'sequence' functions asking for class/values/index
		*$AUTOLOAD = sub {return $_[0]->{$type}{$val}};	
		goto &$AUTOLOAD;
	} else {die '[Nmap-Parser] method ->'.$param."() not defined!\n";}
}


#/*****************************************************************************/
# NMAP::PARSER::HOST::SERVICE
#/*****************************************************************************/

package JR::Parsers::Nmap::Host::Service;
use vars qw($AUTOLOAD);

sub new {
my $class = shift;
$class    = ref($class) || $class;
my $self  =  shift      || {};
bless ($self,$class);
return $self;
}


#Support for:
#name port proto rpcnum owner version product extrainfo tunnel method confidence
#this will now only load functions that will be used. This saves
#on delay (increase speed) and memory

sub AUTOLOAD {
	(my $param = $AUTOLOAD) =~ s{.*::}{}xms;
	return if($param eq 'DESTROY');
	no strict 'refs';
	
	*$AUTOLOAD = sub {return $_[0]->{lc $param}};	
	goto &$AUTOLOAD;
}


#/*****************************************************************************/
# NMAP::PARSER::HOST::OS
#/*****************************************************************************/


package JR::Parsers::Nmap::Host::OS;
use vars qw($AUTOLOAD);

sub new {
my $class = shift;
$class    = ref($class) || $class;
my $self  =  shift      || {};
bless ($self,$class);
return $self;
}

sub portused_open   {return $_[0]->{portused}{open};} 
sub portused_closed {return $_[0]->{portused}{closed};}
sub os_fingerprint  {return $_[0]->{os_fingerprint};}

sub name_count {return $_[0]->{osmatch_count};}

sub all_names {
    my $self = shift;
    @_=();
    if($self->{osclass_count} < 1){return @_;}
    if(ref($self->{osmatch_name}) eq 'ARRAY'){
    return sort @{$self->{osmatch_name}};}

} #given by decreasing accuracy

sub class_count {return $_[0]->{osclass_count};}

#Support for:
#name,names, name_accuracy, osfamily, vendor, type, osgen, class_accuracy
sub AUTOLOAD {
	(my $param = $AUTOLOAD) =~ s{.*::}{}xms;
	return if($param eq 'DESTROY');
	no strict 'refs';
	$param = lc($param);
	
	$param = 'name' if($param eq 'names');
	if($param eq 'name' || $param eq 'name_accuracy'){
		
		*$AUTOLOAD = sub {_get_info($_[0],$_[1],$param,'osmatch');};		
		goto &$AUTOLOAD;
	} else {

		*$AUTOLOAD = sub {_get_info($_[0],$_[1],$param,'osclass');};	
		goto &$AUTOLOAD;
	}
}

sub _get_info {
	my($self,$index,$param,$type) = @_;
	$index ||= 0;
	#type is either osclass or osmatch
	if($index >= $self->{$type.'_count'}){$index = $self->{$type.'_count'}-1;}
	return $self->{$type.'_'.$param}[$index];		
}

1;

__END__

=pod

=head1 NAME

JR::Parsers::Nmap - parse nmap scan data with perl

=head1 SYNOPSIS

  use JR::Parsers::Nmap;
  my $np = new JR::Parsers::Nmap;
  
  $np->parsescan($nmap_path, $nmap_args, @ips);
    #or
  $np->parsefile($file_xml);
  
  my $session    = $np->get_session();
    #a JR::Parsers::Nmap::Session object
    
  my $host       = $np->get_host($ip_addr);
    #a JR::Parsers::Nmap::Host object
    
  my $service = $host->tcp_service(80);
    #a JR::Parsers::Nmap::Host::Service object
    
  my $os         = $host->os_sig();
    #a JR::Parsers::Nmap::Host::OS object
 
 #---------------------------------------
 
 my $np2 = new JR::Parsers::Nmap;
 
 $np2->callback(\&my_callback);
 
 $np2->parsefile($file_xml);
    #or
 $np2->parsescan($nmap_path, $nmap_args, @ips);
    
 sub my_callback {
 
   my $host = shift;
    #JR::Parsers::Nmap::Host object
    #.. see documentation for all methods ...

 }


I<For a full listing of methods see the documentation corresponding to each object.>

=head1 DESCRIPTION

This module implements a interface to the information contained in an nmap scan.
It is implemented by parsing the xml scan data that is generated by nmap. This
will enable anyone who utilizes nmap to quickly create fast and robust security scripts
that utilize the powerful port scanning abilities of nmap.

=head1 OVERVIEW

This module has an internal framework to make it easy to retrieve the desired information of a scan.
Every nmap scan is based on two main sections of informations: the scan session, and the scan information of all hosts.
The session information will be stored as a JR::Parsers::Nmap::Session object. This object will contain its own methods
to obtain the desired information. The same is true for any hosts that were scanned using the JR::Parsers::Nmap::Host object.
There are two sub objects under JR::Parsers::Nmap::Host. One is the JR::Parsers::Nmap::Host::Service object which will be used to obtain
information of a given service running on a given port. The second is the JR::Parsers::Nmap::Host::OS object which contains the
operating system signature information (OS guessed names, classes, osfamily..etc).

  JR::Parsers::Nmap                        -- Core parser
     |
     +--JR::Parsers::Nmap::Session         -- Nmap scan session information
     |  
     +--JR::Parsers::Nmap::Host            -- General host information
     |  |
     |  |-JR::Parsers::Nmap::Host::Service -- Port service information
     |  |
     |  |-JR::Parsers::Nmap::Host::OS      -- Operating system signature information


=head1 METHODS

=head2 JR::Parsers::Nmap

The main idea behind the core module is, you will first parse the information
and then extract data. Therefore, all parse*() methods should be executed before
any get_*() methods.

=over 4


=item B<parse($string)>

=item B<parse($filehandle)>

Parses the nmap scan information in $string. Note that is usually only used if
you have the whole xml scan information in $string or if you are piping the
scan information.

=item B<parsefile($xml_file)>

Parses the nmap scan data in $xml_file. This file can be generated from an nmap
scan by using the '-oX filename.xml' option with nmap. If you get an error or your program dies due to parsing, please check that the
xml information is compliant. The file is closed no matter how C<parsefile()> returns.

=item B<parsescan($nmap,$args,@ips)>

This method runs an nmap scan where $nmap is the path to the nmap executable,
$args are the nmap command line parameters, and @ips are the list of IP addresses
to scan. parsescan() will automagically run the nmap scan and parse the information.
I<See section EXAMPLES for a short tutorial>

I<Note: You cannot have one of the nmap options to be '-oX', '-oN' or '-oG'. Your
program will die if you try and pass any of these options because it decides the
type of output nmap will generate. The IP addresses can be nmap-formatted
addresses (see nmap(1)>

If you get an error or your program dies due to parsing, please check that the
xml information is compliant. If you are using parsescan() or an open filehandle
, make sure that the nmap scan that you are performing is successful in returning
xml information. (Sometimes using loopback addresses causes nmap to fail).

=item B<purge()>

Cleans the xml scan data from memory. This is useful if you have a program where
you are parsing lots of nmap scan data files with persistent variables.

=item B<callback(\&code_ref)>

Sets the parsing mode to be done using the callback function. It takes the parameter
of a code reference or a reference to a function. If no code reference is given,
it resets the mode to normal (no callback).
 
 $np->callback(\&my_function); #sets callback, my_function() will be called
 $np->callback(); #resets it, no callback function called. Back to normal.


=item B<get_session()>

Obtains the JR::Parsers::Nmap::Session object which contains the session scan information.

=item B<get_host($ip_addr)>

Obtains the JR::Parsers::Nmap::Host object for the given $ip_addr.

=item B<del_host($ip_addr)>

Deletes the stored JR::Parsers::Nmap::Host object whose IP is $ip_addr.

=item B<all_hosts()>

=item B<all_hosts($status)>

Returns an array of all the JR::Parsers::Nmap::Host objects for the scan. If the optional
status is given, it will only return those hosts that match that status. The status
can be any of the following: C<(up|down|unknown|skipped)>

=item B<get_ips()>

=item B<get_ips($status)>

Returns the list of IP addresses that were scanned in this nmap session. They are
sorted using ipv4_sort. If there are IPv6 addresses, or mixed, it might not be
in correct sorted order. If the optional status is given, it will only return
those IP addresses that match that status. The status can be any of the
following: C<(up|down|unknown|skipped)>

=item B<ipv4_sort(@ips)>

This function takes a list of IPv4 addresses and returns the correctly sorted
version of the list.

=back

=head2 JR::Parsers::Nmap::Session

This object contains the scan session information of the nmap scan.


=over 4


=item B<finish_time()>

Returns the numeric time that the nmap scan finished.

=item B<nmap_version()>

Returns the version of nmap used for the scan.

=item B<numservices()>

=item B<numservices($type)>

If numservices is called without argument, it returns the total number of services
that were scanned for all types. If $type is given, it returns the number of services
for that given scan type. See scan_types() for more info.

=item B<scan_args()>

Returns a string which contains the nmap executed command line used to run the
scan.

=item B<scan_type_proto($type)>

Returns the protocol type of the given scan type (provided by $type). See scan_types() for
more info.

=item B<scan_types()>

Returns the list of scan types that were performed. It can be any of the following:
C<(syn|ack|bounce|connect|null|xmas|window|maimon|fin|udp|ipproto)>.

=item B<start_str()>

Returns the human readable format of the start time.

=item B<start_time()>

Returns the numeric form of the time the nmap scan started.

=item B<time_str()>

Returns the human readable format of the finish time.

=item B<xml_version()>

Returns the version of nmap xml file.

=back

=head2 JR::Parsers::Nmap::Host

This object represents the information collected from a scanned host.


=over 4

=item B<status()>

Returns the state of the host. It is usually one of these
C<(up|down|unknown|skipped)>.

=item B<addr()>

Returns the main IP address of the host. This is usually the IPv4 address. If
there is no IPv4 address, the IPv6 is returned (hopefully there is one).

=item B<addrtype()>

Returns the address type of the address given by addr() .

=item B<all_hostnames()>

Returns a list of all hostnames found for the given host.

=item B<extraports_count()>

Returns the number of extraports found.

=item B<extraports_state()>

Returns the state of all the extraports found.

=item B<hostname()>

=item B<hostname($index)>

As a basic call, hostname() returns the first hostname obtained for the given
host. If there exists more than one hostname, you can provide a number, which
is used as the location in the array. The index starts at 0;

 #in the case that there are only 2 hostnames
 hostname() eq hostname(0);
 hostname(1); #second hostname found
 hostname(400) eq hostname(1) #nothing at 400; return the name at the last index
 

=item B<ipv4_addr()>

Explicitly return the IPv4 address.

=item B<ipv6_addr()>

Explicitly return the IPv6 address.

=item B<mac_addr()>

Explicitly return the MAC address.

=item B<mac_vendor()>

Return the vendor information of the MAC.

=item B<distance()>

Return the distance (in hops) of the target machine from the machine that performed the scan.

=item B<os_sig()>

Returns an JR::Parsers::Nmap::Host::OS object that can be used to obtain all the
Operating System signature (fingerprint) information. See JR::Parsers::Nmap::Host::OS
for more details.

 $os = $host->os_sig;
 $os->name;
 $os->osfamily;

=item B<tcpsequence_class()>

=item B<tcpsequence_index()>

=item B<tcpsequence_values()>

Returns the class, index and values information respectively of the tcp sequence.

=item B<ipidsequence_class()>

=item B<ipidsequence_values()>

Returns the class and values information respectively of the ipid sequence.

=item B<tcptssequence_class()>

=item B<tcptssequence_values()>

Returns the class and values information respectively of the tcpts sequence.

=item B<uptime_lastboot()>

Returns the human readable format of the timestamp of when the host had last
rebooted.

=item B<uptime_seconds()>

Returns the number of seconds that have passed since the host's last boot from
when the scan was performed.


=item B<tcp_ports()>

=item B<udp_ports()>

Returns the sorted list of TCP|UDP ports respectively that were scanned on this host. Optionally
a string argument can be given to these functions to filter the list.

 $host->tcp_ports('open') #returns all only 'open' ports (even 'open|filtered')
 $host->udp_ports('open|filtered'); #matches exactly ports with 'open|filtered'
 
I<Note that if a port state is set to 'open|filtered' (or any combination), it will
be counted as an 'open' port as well as a 'filtered' one.>

=item B<tcp_port_count()>

=item B<udp_port_count()>

Returns the total of TCP|UDP ports scanned respectively.

=item B<tcp_port_state($portid)>

=item B<udp_port_state($portid)>

Returns the state of the given port, provided by the port number in $portid.


=item B<tcp_open_ports()>

=item B<udp_open_ports()>

Returns the list of open TCP|UDP ports respectively. Note that if a port state is
for example, 'open|filtered', it will appear on this list as well. 

=item B<tcp_filtered_ports()>

=item B<udp_filtered_ports()>

Returns the list of filtered TCP|UDP ports respectively. Note that if a port state is
for example, 'open|filtered', it will appear on this list as well. 

=item B<tcp_closed_ports()>

=item B<udp_closed_ports()>

Returns the list of closed TCP|UDP ports respectively. Note that if a port state is
for example, 'closed|filtered', it will appear on this list as well. 

=item B<tcp_service($portid)>

=item B<udp_service($portid)>

Returns the JR::Parsers::Nmap::Host::Service object of a given service running on port,
provided by $portid. See JR::Parsers::Nmap::Host::Service for more info. 

 $svc = $host->tcp_service(80);
 $svc->name;
 $svc->proto;
 

=back

=head3 JR::Parsers::Nmap::Host::Service

This object represents the service running on a given port in a given host. This
object is obtained by using the tcp_service($portid) or udp_service($portid) method from the
JR::Parsers::Nmap::Host object. If a portid is given that does not exist on the given
host, these functions will still return an object (so your script doesn't die).
Its good to use tcp_ports() or udp_ports() to see what ports were collected.

=over 4


=item B<confidence()>

Returns the confidence level in service detection.

=item B<extrainfo()>

Returns any additional information nmap knows about the service.

=item B<method()>

Returns the detection method.

=item B<name()>

Returns the service name.

=item B<owner()>

Returns the process owner of the given service. (If available)

=item B<port()>

Returns the port number where the service is running on.

=item B<product()>

Returns the product information of the service.

=item B<proto()>

Returns the protocol type of the service.

=item B<rpcnum()>

Returns the RPC number.

=item B<tunnel()>

Returns the tunnel value. (If available)

=item B<fingerprint()>

Returns the service fingerprint. (If available)

=back
 
=item B<version()>

Returns the version of the given product of the running service.

=back

=head3 JR::Parsers::Nmap::Host::OS

This object represents the Operating System signature (fingerprint) information
of the given host. This object is obtained from an JR::Parsers::Nmap::Host object
using the C<os_sig()> method. One important thing to note is that the order of OS
names and classes are sorted by B<DECREASING ACCURACY>. This is more important than
alphabetical ordering. Therefore, a basic call
to any of these functions will return the record with the highest accuracy.
(Which is probably the one you want anyways).

=over 4

=item B<all_names()>

Returns the list of all the guessed OS names for the given host.

=item B<class_accuracy()>

=item B<class_accuracy($index)>

A basic call to class_accuracy() returns the osclass accuracy of the first record.
If C<$index> is given, it returns the osclass accuracy for the given record. The
index starts at 0.

=item B<class_count()>

Returns the total number of OS class records obtained from the nmap scan.

=item B<name()>

=item B<name($index)>

=item B<names()>

=item B<names($index)>

A basic call to name() returns the OS name of the first record which is the name
with the highest accuracy. If C<$index> is given, it returns the name for the given record. The
index starts at 0.

=item B<name_accuracy()>

=item B<name_accuracy($index)>

A basic call to name_accuracy() returns the OS name accuracy of the first record. If C<$index> is given, it returns the name for the given record. The
index starts at 0.

=item B<name_count()>

Returns the total number of OS names (records) for the given host.

=item B<osfamily()>

=item B<osfamily($index)>

A basic call to osfamily() returns the OS family information of the first record.
If C<$index> is given, it returns the OS family information for the given record. The
index starts at 0.

=item B<osgen()>

=item B<osgen($index)>

A basic call to osgen() returns the OS generation information of the first record.
If C<$index> is given, it returns the OS generation information for the given record. The
index starts at 0.

=item B<portused_closed()>

Returns the closed port number used to help identify the OS signatures. This might not
be available for all hosts.

=item B<portused_open()>

Returns the open port number used to help identify the OS signatures. This might
not be available for all hosts.

=item B<os_fingerprint()>

Returns the OS fingerprint used to help identify the OS signatures. This might not be available for all hosts.

=item B<type()>

=item B<type($index)>

A basic call to type() returns the OS type information of the first record.
If C<$index> is given, it returns the OS type information for the given record. The
index starts at 0.

=item B<vendor()>

=item B<vendor($index)>

A basic call to vendor() returns the OS vendor information of the first record.
If C<$index> is given, it returns the OS vendor information for the given record. The
index starts at 0.

=back

=head1 EXAMPLES

I think some of us best learn from examples. These are a couple of examples to help
create custom security audit tools using some of the nice features
of the JR::Parsers::Nmap module. Hopefully this can double as a tutorial. 
More tutorials (articles) can be found at L<nmapparser.wordpress.com>

=head2 Real-Time Scanning - (no better C<time()> like C<'now'>)

You can run a nmap scan and have the parser parse the information automagically.
The only constraint is that you cannot use '-oX', '-oN', or '-oG' as one of your
arguments for nmap command line parameters passed to parsescan().

 use JR::Parsers::Nmap;

 my $np = new JR::Parsers::Nmap;
 my @hosts = @ARGV; #get hosts from cmd line

 #runs the nmap command with hosts and parses it automagically
 $np->parsescan('/usr/bin/nmap','-sS O -p 1-1023',@hosts);

 for my $host ($np->all_hosts()){
 	print $host->hostname."\n";
	#do mor stuff...
 }
 

=head2 Callbacks - (C<not our $normal *69>)

This is probably the easiest way to write a script with using JR::Parsers::Nmap,
if you don't need the general scan session information. During the parsing
process, the parser will obtain information of every host. The
callback function (in this case 'booyah()')  is called after the parsing of
every host (sequentially). When the callback returns, the parser will delete all
information of the host it had sent to the callback. This callback function is
called for every host that the parser encounters. I<The callback function must be
setup before parsing>

 use JR::Parsers::Nmap;
 my $np = new JR::Parsers::Nmap;

 
 $np->callback( \&booyah );
 
 $np->parsefile('nmap_results.xml');
    # or use parsescan()

 sub booyah {
    my $host = shift; #JR::Parsers::Nmap::Host object, just parsed
    print 'IP: ',$host->addr,"\n";
	 # ... do more stuff with $host ...

    #when it returns, host object will be deleted from memory
    #(good for processing VERY LARGE files or scans)
 }
 

=head2 Multiple Instances - (C<no less 'of'; my $self>)

Using multiple instances of JR::Parsers::Nmap is extremely useful in helping
audit/monitor the network B<P>olicy (ohh noo! its that 'P' word!).
In this example, we have a set of hosts that had been scanned previously for tcp
services where the image was saved in I<base_image.xml>. We now will scan the
same hosts, and compare if any new tcp have been open since then
(good way to look for suspicious new services). Easy security B<C>ompliance detection.
(ooh noo! The 'C' word too!).


 use JR::Parsers::Nmap;
 use vars qw($nmap_exe $nmap_args @ips);
 my $base = new JR::Parsers::Nmap;
 my $curr = new JR::Parsers::Nmap;
 
 
 $base->parsefile('base_image.xml'); #load previous state
 $curr->parsescan($nmap_exe, $nmap_args, @ips); #scan current hosts
 
 for my $ip ($curr->get_ips ) 
 {
 	#assume that IPs in base == IPs in curr scan
 	my $ip_base = $base->get_host($ip);
 	my $ip_curr = $curr->get_host($ip);
 	my %port = ();
 	
 	#find ports that are open that were not open before
 	#by finding the difference in port lists
	my @diff =  grep { $port{$_} < 2} 
		   (map {$port{$_}++; $_} 
		   ( $ip_curr->tcp_open_ports , $ip_base->tcp_open_ports ));
	
	print "$ip has these new ports open: ".join(',',@diff) if(scalar @diff);
	
	for (@diff){print "$_ seems to be ",$ip_curr->tcp_service($_)->name,"\n";}
 		
 }
 

=head1 SUPPORT

=head2 Discussion Forum

If you have questions about how to use the module, or any of its features, you
can post messages to the JR::Parsers::Nmap module forum on CPAN::Forum.
L<http://www.cpanforum.com/dist/Nmap-Parser>

=head2 Bug Reports

Please submit any bugs to:
L<http://code.google.com/p/nmap-parser/issues/list>

B<Please make sure that you submit the xml-output file of the scan which you are having
trouble.> This can be done by running your scan with the I<-oX filename.xml> nmap switch.
Please remove any important IP addresses for security reasons.

=head1 SEE ALSO

 nmap, XML::Twig

The JR::Parsers::Nmap page can be found at: L<http://nmapparser.wordpress.com> or L<http://code.google.com/p/nmap-parser/>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>.

=head1 AUTHOR

Anthony G Persaud

=head1 COPYRIGHT

Copyright (c) <2007> <Anthony G. Persaud>

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

=cut
