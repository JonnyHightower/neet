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

# NOT USED IN NEET > 0.5

# CPCE - Cross Platform Command Execution Library
# by JR. phlux@packetsnarf.net

# This version implements PROTOCOL 2, which has the challenge-response
# authentication.

# VERSION 2.0.1

use strict;
use IO::Socket::INET;

# *******************
# *** Server Code ***
# ~~~~~~~~~~~~~~~~~~~

package CPCEServer;

sub new {
	# CPCEServer object constructor
	# my $Server=CPCEServer->new(); Optional parameters are LogFile, CPCEPort, Timeout (in seconds), ListenAddress
	# my $Server=CPCEServer->new('ListenAddress'=>'127.0.0.1', 'Timeout'=>5, 'LogFile'=>"C:\\rcedlog.txt", 'CPCEPort'=>'1025');
	my $self=shift();
	my %rpc=@_;
	my %clients;
	$rpc{'Version'}="2.0.1";
	# Default timeout
	if ( !CPCECrypt::is_int($rpc{'Timeout'}) ){
		$rpc{'Timeout'}=3;
	}
	# Default CPCE Port
	if ( !CPCECrypt::is_port($rpc{'CPCEPort'}) ){
		$rpc{'CPCEPort'}=65467;
	}
	# Default Listen Address
	if ( !CPCECrypt::is_ip($rpc{'ListenAddr'}) ){
		$rpc{'ListenAddr'}='0.0.0.0';
	}
	$rpc{'clients'}=\%clients;
	my $object=\%rpc;
	bless $object, $self;
	return $object;
}

sub AddClient {
	# Adds clients to the CPCEServer object's list of permitted clients (a key or keyfile must
	# be specified for each client)
	# $Server->AddClient('IP' => '192.168.10.2', 'Key'='1234567890');
	# OR
	# $Server->AddClient('IP' => '192.168.10.2', 'KeyFile'='pre-shared.key');
	my $self=shift();
	my %client=@_;
	if (CPCECrypt::is_ip($client{'IP'})){
		# Check that we have a key specified
		if (defined($client{'Key'})){
			${$$self{'clients'}}{$client{'IP'}}{'valid'}=1;
			${$$self{'clients'}}{$client{'IP'}}{'Key'}=$client{'Key'};
		} elsif (defined($client{'KeyFile'})){
			if (open(KEY,$client{'KeyFile'})){
				my $key=<KEY>;
				close KEY;
				${$$self{'clients'}}{$client{'IP'}}{'valid'}=1;
				${$$self{'clients'}}{$client{'IP'}}{'Key'}=$key;
			}
		} else {
			return 0;
		}
		return 1;
	}
	return 0;
}

sub DelClient {
	# Removes clients
	# $Server->DelClient('IP' => '192.168.10.2');
	my $self=shift();
	my %client=@_;
	if (CPCECrypt::is_ip($client{'IP'}) && (${$$self{'clients'}}{$client{'IP'}}{'valid'})){
		${$$self{'clients'}}{$client{'IP'}}{'valid'}=0;
		${$$self{'clients'}}{$client{'IP'}}{'Key'}=undef;
		return 1;
	}
	return 0;
}

sub Accept {
	# This will use IO::Socket to listen on the specified IP address and handle incoming
	# connections. A new child will be forked to handle each incoming connection.
	my $self=shift();
	# Exit if there are no clients
	my $num_clients=0;
	for my $a (keys(%{$$self{'clients'}})){
		$num_clients++;
	}
	if (!$num_clients){
		$self->Log("CPCE Server - no point listening when no clients are allowed to conenct.\n");
		return 0;		
	}
	# Listen
	my $clients=join ",", keys(%{$$self{'clients'}});

	$self->Log("Server binding to $$self{'ListenAddr'} Port $$self{'CPCEPort'}. Accepting from $clients on a $$self{'Timeout'} second timeout.\n");

	my $Socket=IO::Socket::INET->new ('Listen' => 5, 'LocalAddr' => $$self{'ListenAddr'}, 
									'LocalPort' => $$self{'CPCEPort'}, 'Proto'=>'tcp', 'ReuseAddr'=>'1', 'Timeout'=>$$self{'Timeout'});
	if (!$Socket) {
		print STDERR ("Couldn't bind to port $$self{'CPCEPort'}\n");
		$self->Log("Couldn't bind to port $$self{'CPCEPort'}\n");
		return undef;
	} else {
		$$self{'listening'}=1;
		$self->Log("CPCE Server bound to $$self{'ListenAddr'} listening on port $$self{'CPCEPort'}. Accepting connections from $clients\n");
		$$self{'Socket'}=$Socket;

		# Listen and accept connections. When a client connects, fork and pass control to HandleClient().
		while (1){
			while (my $Client = $Socket->accept()){
				my $cpid=fork();
				if (!$cpid){
					$self->HandleClient($Client);
					exit;
				}
			}
		}

		$$self{'listening'}=0;
		print "CPCE Server is exiting\n";
		$Socket->Close;
		exit 0;
	}
}

sub HandleClient {
	# Used internally - called by Accept().
	my $self=shift();
	# Client socket object
	my $Client=shift();
	my $peer=$Client->peerhost;
	# Close connection if the client isn't in our valid list
	if (!$self->ClientAllowed("$peer")){
		$self->Log("Server got illegal connection from $peer\n");
		$Client->close;
		return undef;
	}
	# Start of the cryptographic challenge-response
	# Generate a nonce, store it, and send a copy to the client
	${$$self{'clients'}}{$peer}{'Ns'}=CPCECrypt::nonce();
	${$$self{'clients'}}{$peer}{'socket'}=$Client;
	$$self{'current'}=$peer;
	my $msg=CPCECrypt::Digest(${$$self{'clients'}}{$peer}{'Key'} . ${$$self{'clients'}}{$peer}{'Ns'}) . ${$$self{'clients'}}{$peer}{'Ns'};
	# Send the challenge to the client
	print $Client $msg . "\n";
	# Get the reply
	$msg=<$Client>;
	# Check it's signed by the correct key for the client
	my $data=$self->Verify($msg);
	if (!$data){
		# Oops. Wrong key
		$self->Log("Message from $peer failed authentication\n");
		return undef;	
	}
	# Trim trailing whitespace and execute command
   local( $/ ); $data =~ s/\s{1,}$//;

	if ("$data" eq "rpc_prot_check"){
		# Allow for an OS-independant protocol check
		my $output="rpc_prot_check_ok\n";
		my $SRES=CPCECrypt::Digest(${$$self{'clients'}}{$peer}{'Key'} . ${$$self{'clients'}}{$peer}{'Nc'} . ${$$self{'clients'}}{$peer}{'Ns'} . $output) . $output;
		$self->Log("$peer requested protocol check\n");
		print $Client $SRES;
	} else {
		# Execute the command
		$self->Log("Executing $data for $peer\n");
		my $output=`$data 2>&1`;
		if (!defined($output)){
			$output="";
			# This is likely to be if the command doesn't exist on the system
			$self->Log("Execution of $data for $peer produced no output\n");
		}
		# Sign the results...
		my $SRES=CPCECrypt::Digest(${$$self{'clients'}}{$peer}{'Key'} . ${$$self{'clients'}}{$peer}{'Nc'} . ${$$self{'clients'}}{$peer}{'Ns'} . $output) . $output;
		# And send them back to the client
		print $Client $SRES;
	}
	# Close and return
	$Client->close;
	return 0;
}

sub ClientAllowed {
	# Use to determine if a particular client is allowed to connect
	# if ($Server->ClientAllowed("192.168.1.3")){
	my $self=shift();
	my $Client=shift();
	if (defined(${$$self{'clients'}}{$Client}{'valid'}) && (${$$self{'clients'}}{$Client}{'valid'} == 1)  ){
		return 1;
	}
	return 0;
}

sub Log {
	# Logging and output
	my $self=shift();
	my $msg=shift();
	print STDERR $msg;
	if (defined($$self{'LogFile'}) && (open(LOG,">>$$self{'LogFile'}")) ){
		print LOG localtime() . ": $msg";
		close LOG;
	}
}

sub Verify {
	# Used internally to determine if the client correctly signed the command request
	my $self=shift();
	my $rcv_msg=shift();
	my $peer=$$self{'current'};
	return undef if (!$rcv_msg);
	# Message length: 64 (bytes of hash) + 12 (bytes of nonce) + 2 (minimum command length)
	if (length($rcv_msg) < (64 + 12 + 2)){
		return undef;
	}
	my $rcv_digest=substr($rcv_msg,0,64);
	${$$self{'clients'}}{$peer}{'Nc'}=substr($rcv_msg,64,12);
	my $data=substr($rcv_msg,(12+64),length($rcv_msg)-(12+64));
	my $digest=CPCECrypt::Digest( ${$$self{'clients'}}{$peer}{'Key'} . ${$$self{'clients'}}{$peer}{'Nc'} . ${$$self{'clients'}}{$peer}{'Ns'} . $data );
	if ("$digest" eq "$rcv_digest"){
		return $data;
	}
	return undef;
}

sub Version {
	my $self=shift();
	return $$self{'Version'};
}

# *******************
# *** Client Code ***
# ~~~~~~~~~~~~~~~~~~~

package CPCEClient;

sub new {
	# CPCEClient object constructor
	# my $Client=CPCEClient->new('ServerAddress'=>'127.0.0.1', 'Key'=>'123456');
	# my $Client=CPCEClient->new('ServerAddress'=>'127.0.0.1', 'KeyFile'=>'key.txt','CPCEPort'='22','Timeout'=>5);
	my $self=shift();
	my %rpc=@_;
	# Default timeout
	if ( !CPCECrypt::is_int($rpc{'Timeout'}) ){
		$rpc{'Timeout'}=3;
	}
	# CPCE Port
	if ( !CPCECrypt::is_port($rpc{'CPCEPort'}) ){
		$rpc{'CPCEPort'}=65467;
	}
	# Server Addr
	if ( !CPCECrypt::is_ip($rpc{'ServerAddr'}) ){
		return undef;
	}
	# Key 
	if ( !$rpc{'Key'} ){
		# Read the KeyFile if it's specified, and overwrite Key with the contents
		if ($rpc{'KeyFile'} && open(KEY,$rpc{'KeyFile'})){
			my $key=<KEY>;
			close KEY;
			$rpc{'Key'}=$key;
		} else {
			return undef;
		}
	}
	my $object=\%rpc;
	bless $object, $self;
	return $object;
}

sub RemoteExec {
	# Connects to the server and executes the command
	# my $output=$Client->RemoteExec("command");
	my $self=shift();
	my $cmd=shift();
	if ($cmd !~ /\n$/){
		$cmd .= "\n";
	}
	# Connect
	my $Socket=IO::Socket::INET->new('PeerAddr'=>$$self{'ServerAddr'}, 'PeerPort'=>$$self{'CPCEPort'}, 'Proto'=>'tcp', 'Timeout'=>$$self{'Timeout'});
	if (!$Socket){
		print STDERR "Couldn't connect to peer $$self{'ServerAddr'}:$$self{'CPCEPort'}\n";
		return undef;
	}
	# Get the challenge
	my $msg=<$Socket>; 
	if (!defined($msg)){ $msg = ""; }
	chomp $msg;
	# Check that the challenge was correctly signed with our key
	my $Ns = $self->VerifyNs($msg);
	if ($Ns){
		# Yes it was. Store the server challenge. Generate and store our own as well.
		$$self{'Ns'}=$Ns;
		$$self{'Nc'}=CPCECrypt::nonce();
		# Sign the command
		my $sign=CPCECrypt::Digest($$self{'Key'} . $$self{'Nc'} .$$self{'Ns'} . $cmd);
		# Send our challenge, the command and the signature
		my $send=$sign . $$self{'Nc'} . $cmd;
		print $Socket "$send";
		# Get the results
		local( $/ );
		my $output=<$Socket>;
		# Check they are properly signed.
		$output=$self->VerifyRes($output);
		$Socket->close;
		return $output;
	} else {
		# Challenge didn't appear to be signed with our key.
		print STDERR "Authentication Failure - command not executed.\n";
		$Socket->close;
	}
		
	return undef;

}

sub VerifyNs {
	# Used internally to check that the challenge sent be the server was
	# correctly signed.
	my $self=shift();
	my $rcv_msg=shift();
	return undef if (!$rcv_msg);
	# Message length: 64 (bytes of hash) + 12 (bytes of nonce)
	if (length($rcv_msg) < (64 + 12)){
		return undef;
	}
	my $rcv_digest=substr($rcv_msg,0,64);
	my $ServerNonce=substr($rcv_msg,64,12);
	my $digest=CPCECrypt::Digest($$self{'Key'} . $ServerNonce);
	if ("$digest" eq "$rcv_digest"){
		return $ServerNonce;
	}
	return undef;
}

sub VerifyRes {
	# Used internally to check that the output of the command was signed properly.
	my $self=shift();
	my $rcv_msg=shift();
	return undef if (!$rcv_msg);
	if (length($rcv_msg) < 64){
		return undef;
	}
	my $rcv_digest=substr($rcv_msg,0,64);
	my $results=substr($rcv_msg,64,(length($rcv_msg)-64));
	my $digest=CPCECrypt::Digest($$self{'Key'} . $$self{'Nc'} .$$self{'Ns'} . $results);
	if ("$digest" eq "$rcv_digest"){
		return $results;
	}
	print STDERR "Authentication Failure - results not accepted by client.\n";
	return undef;
}

# *******************
# *** Common Code ***
# ~~~~~~~~~~~~~~~~~~~

package CPCECrypt;

use Digest::SHA qw(sha256_hex);

sub Digest {
	# So we can change the hashing function if we want and only have to change it here.
	my @data=@_;
	my $a; for my $b (@data) {
		$a .= $b;
	}
	my $digest=sha256_hex($a);
	return $digest;
}
sub nonce {
	# Generate a nonce.
	my $iv="";
	for (my $a=0; $a<6; $a++){
		# The 31 is to try and get it within the ascii range
		$iv .= sprintf ("%x", (int(rand(200))+31));
	}
	return $iv;
}
sub is_ip {
	# Check it's an IP address (IPv4)
	my $ip=shift();
	if ($ip && $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
		return 1;
	}
	return 0;
}
sub is_port {
	# Check it's a valid port number
	my $port=shift();
	if ($port && ($port =~ /^\d{1,5}$/) && ($port > 0) && ($port < 65536)){
		return 1;
	}
	return 0;
}
sub is_int {
	# Check it's an integer
	my $int=shift();
	if (defined($int) && ($int =~ /^\d{1,5}$/) && ($int > -1) && ($int < 65536)){
		return 1;
	}
	return 0;
}

1;
