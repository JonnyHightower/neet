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

# This is the module that constructs and maintains RCE objects.
# This version implements PROTOCOL 1.

# NOT USED IN NEET > 0.6

package RCE;
use strict;
use IO::Socket::INET;
use Digest::SHA qw(sha256_hex);

sub new {
	my $self=shift();
	my $valid=0;
	my %rpc=@_;

	# Debugging
	if ( !$self->is_int($rpc{'Debug'}) ){
		$rpc{'Debug'}=0;
	}

	# Default timeout
	if ( !$self->is_int($rpc{'Timeout'}) ){
		$rpc{'Timeout'}=3;
	}
	# RCE Port
	if ( !$self->is_port($rpc{'RCEPort'}) ){
		$rpc{'RCEPort'}=65467;
	}

	# Listen Address
	if ( !$self->is_ip($rpc{'ListenAddr'}) ){
		$rpc{'ListenAddr'}='0.0.0.0';
	}

	# Key
	$rpc{'SigningKey'}=undef;

	if ( defined($rpc{'KeyFile'}) ){
		if (open(KEY,$rpc{'KeyFile'})) {

			print "DEBUG -> Opened KeyFile $rpc{'KeyFile'}\n" if (defined($rpc{'Debug'}) && $rpc{'Debug'}>2);

			$rpc{'SigningKey'}=<KEY>;
			close KEY;
		} else {
			print "Couldn't open KeyFile $rpc{'KeyFile'}\n";
		}
	} elsif ( defined($rpc{'Key'}) ){
		$rpc{'SigningKey'}=$rpc{'Key'};
	}

	# Determine role
	if ( defined($rpc{'SigningKey'}) ){

		if ( $self->is_ip($rpc{'ClientAddr'}) ){
			$valid=1;
			$rpc{'server'}=1;
			$rpc{'listening'}=0;
			$rpc{'client'}=0;

			print "DEBUG -> Started as Server role\n" if (defined($rpc{'Debug'}) && $rpc{'Debug'}>2);

		} elsif ( $self->is_ip($rpc{'ServerAddr'}) ){
			$valid=1;
			$rpc{'client'}=1;
			$rpc{'server'}=0;

			print "DEBUG -> Started as Client role\n" if (defined($rpc{'Debug'}) && $rpc{'Debug'}>2);

		}
	}

	return 0 if (!$valid);
	$rpc{'IVSize'}=16;
	my $object=\%rpc;
	bless $object, $self;
	return $object;

}

# **** Client Code ****
# ^^^^^^^^^^^^^^^^^^^^^
sub Execute {
	my $self=shift();
	my $cmd=shift();
	if ($cmd !~ /\n$/){
		$cmd .= "\n";
	}
	no strict 'refs';
	my $Socket=IO::Socket::INET->new('PeerAddr'=>$$self{'ServerAddr'}, 'PeerPort'=>$$self{'RCEPort'}, 'Proto'=>'tcp', 'Timeout'=>$$self{'Timeout'});
	if (!$Socket){
		print "Couldn't connect to peer $$self{'ServerAddr'}:$$self{'RCEPort'}\n";
		return undef;
	}
	my $send=$self->Sign($cmd);
	print $Socket "$send";
	local( $/ );
	my $output=<$Socket>;
	$output=$self->Verify($output);
	$Socket->close;
	return $output;
}


# **** Server Code ****
# ^^^^^^^^^^^^^^^^^^^^^

sub Accept {
	# This will run until we get a SIGHUP
	my $self=shift();

	print "DEBUG -> Server binding to $$self{'ListenAddr'} Port $$self{'RCEPort'}. Accepting from $$self{'ClientAddr'} on a $$self{'Timeout'} second timeout.\n"
		 if (defined($$self{'Debug'}) && $$self{'Debug'}>1);

	$self->Log("Server binding to $$self{'ListenAddr'} Port $$self{'RCEPort'}. Accepting from $$self{'ClientAddr'} on a $$self{'Timeout'} second timeout.\n");

	my $Socket=IO::Socket::INET->new ('Listen' => 5, 'LocalAddr' => $$self{'ListenAddr'}, 'LocalPort' => $$self{'RCEPort'}, 'Proto'=>'tcp', 'ReuseAddr'=>'1', 'Timeout'=>$$self{'Timeout'});
	if (!$Socket) {
		print STDERR ("Couldn't bind to port $$self{'RCEPort'}\n");
		$self->Log("Couldn't bind to port $$self{'RCEPort'}\n");
		return undef;
	} else {
		$$self{'listening'}=1;
		print "RCE Server listening on $$self{'ListenAddr'} port $$self{'RCEPort'}\n -> Accepting connections from $$self{'ClientAddr'}\n";
		$self->Log("RCE Server bound to $$self{'ListenAddr'} listening on port $$self{'RCEPort'}. Accepting connections from $$self{'ClientAddr'}\n");
		$$self{'Socket'}=$Socket;
		while (1){
			while (my $Client = $Socket->accept()){
				my $Peer=$Client->peerhost;

				print "DEBUG -> Server got connection from $Peer\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>2);

				my $cpid=fork();
				if (!$cpid){
					$self->HandleClient($Client);
					exit;
				}
			}
		}
		$$self{'listening'}=0;
		print "RCE Server is exiting\n";
		$Socket->Close;
		exit 0;
	}
}


sub HandleClient {
	my $self=shift();
	my $Client=shift();
	my $peer=$Client->peerhost;
	if ("$peer" ne "$$self{'ClientAddr'}"){

		print "DEBUG [Handler] -> Server got illegal connection from $peer\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>1);
		$self->Log("Server got illegal connection from $peer\n");

		$Client->close;
		return undef;
	}

	print "DEBUG [Handler] -> Legal connection from $peer\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>1);

	my $msg=<$Client>;
	my $data=$self->Verify($msg);
	if (!$data){

		print "DEBUG [Handler] -> Illegal message from $peer\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>1);
		$self->Log("Server got illegal message from $peer\n");

		return undef;	
	}
	$self->SingleExec($Client,$data);
	$Client->close;
	return 0;
}

sub SingleExec {
	my $self=shift();
	my $Client=shift();
	my $command=shift();

	chomp $command;

	print "DEBUG [EXEC] -> Executing \"$command\"\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>1);
	$self->Log("Executing \"$command\"\n");

	my $results="";
	if (open (COMMAND,"$command 2>&1 |")){
		while (my $line=<COMMAND>){
			$results .= $line;
		}
		close COMMAND;
		$results=$self->Sign($results);
	}

	print "DEBUG [RESULTS] -> $results\n" if (defined($$self{'Debug'}) && $$self{'Debug'}>3);

	print $Client $results;
	return 0;
}

sub Log {
	my $self=shift();
	my $msg=shift();
	if ($$self{'server'} && defined($$self{'LogFile'}) && (open(LOG,">>$$self{'LogFile'}")) ){
		print LOG localtime() . ": $msg";
		close LOG;
	}
}

# **** Accessors ****
# ^^^^^^^^^^^^^^^^^^^

sub Client {
	my $self=shift();
	return $$self{'client'};
}
sub Server {
	my $self=shift();
	return $$self{'server'};
}
sub Role {
	my $self=shift();
	if ($$self{'server'}){
		return "Server";
	} elsif ($$self{'client'}) {
		return "Client";
	}
	return undef;
}
sub Key {
	my $self=shift();
	return $$self{'SigningKey'};
}
sub KeyFile {
	my $self=shift();
	return $$self{'KeyFile'};
}
sub RCEPort {
	my $self=shift();
	return $$self{'RCEPort'};
}
sub ClientAddr {
	my $self=shift();
	return $$self{'ClientAddr'};
}
sub ServerAddr {
	my $self=shift();
	return $$self{'ServerAddr'};
}
sub ListenAddr {
	my $self=shift();
	return $$self{'ListenAddr'};
}

# **** Modifiers ****
# ^^^^^^^^^^^^^^^^^^^
sub SetClientAddr {
	my $self=shift();
	my $addr=shift();
	if ($self->is_ip($addr) && $$self{'server'} && !$$self{'listening'}){
		$$self{'ClientAddr'}=$addr;
	}
}
sub SetServerAddr {
	my $self=shift();
	my $addr=shift();
	if ($self->is_ip($addr) && $$self{'client'}){
		$$self{'ServerAddr'}=$addr;
	}
}

# **** Common Validation Code ****
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

sub Sign {
	my $self=shift();
	my $data=shift();
	my $iv=$self->iv;
	my $digest=$self->Digest($iv,$data);
	my $newdata=$iv . $digest . $data;
	return $newdata;
}

sub Verify {
	my $self=shift();
	my $rcv_msg=shift();
	if (length($rcv_msg) < (64 + $$self{'IVSize'}) + 2){
		return undef; # Was return 0;
	}
	my $rcv_iv=substr($rcv_msg,0,$$self{'IVSize'});
	my $rcv_digest=substr($rcv_msg,$$self{'IVSize'},64);
	my $data=substr($rcv_msg,($$self{'IVSize'}+64),length($rcv_msg)-($$self{'IVSize'}+64));
	my $digest=$self->Digest($rcv_iv,$data);
	if ("$digest" eq "$rcv_digest"){
		return $data;
	}
	return undef;
}

sub Digest {
	my $self=shift();
	my $iv=shift();
	my $data=shift();
	my $digest=sha256_hex($data);
	$digest=sha256_hex($digest . $$self{'Key'});
	$digest=sha256_hex($digest . $iv);
	return $digest;
}

sub iv {
	my $self=shift();
	my $iv="";
	for (my $a=0; $a<$$self{'IVSize'}/2; $a++){
		$iv .= sprintf ("%x", (int(rand(200))+31));
	}
	return $iv;
}

sub is_ip {
	my $self=shift();
	my $ip=shift();
	if ($ip && $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
		return 1;
	}
	return 0;
}

sub is_port {
	my $self=shift();
	my $port=shift();
	if ($port && ($port =~ /^\d{1,5}$/) && ($port > 0) && ($port < 65536)){
		return 1;
	}
	return 0;
}

sub is_int {
	my $self=shift();
	my $int=shift();
	if (defined($int) && ($int =~ /^\d{1,5}$/) && ($int > -1) && ($int < 65536)){
		return 1;
	}
	return 0;
}

1;
