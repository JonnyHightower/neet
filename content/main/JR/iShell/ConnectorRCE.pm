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

# JR::ConnectorRCE.pm

# This is the RCE connector for the ishell command shell framework.
# Jonathan Roach

# It uses RCE in pure PERL to provide access to a remote box via JR's RCE mechanism

# All connectors should provide the same base interface to the calling iShell.
# new		-> create a new instance of the connector. This should only return a connector object
#		   if the initial connection succeeds
# test		-> test for command shell capabilities. Should return 1 for "yes, we have a shell" or
# 		   otherwise 0
# execute	-> execute this system command - returns an array of output
# ServerTime	-> get the date/time from the server
# OS		-> get the OS version
# Server	-> get the Server version
# Args		-> return a hash of parameters that should be supplied.
# BaseDir	-> get the directory that the exploited service is based
# Environment	-> get a hash of the environment variables
# disconnect	-> Close the connection

package JR::iShell::ConnectorRCE;
use JR::Process::RCE;

sub new {
	my $PKG=shift();
	my %RCE=@_;

	my %RequiredArgs;
	$RequiredArgs{'Args'}="Host Port Key KeyFile";
	$RequiredArgs{'Optional'}="Host Port Key KeyFile";
	$RequiredArgs{'Mandatory'}="";
	$RequiredArgs{'Defaults'}{'Host'}="127.0.0.1";
	$RequiredArgs{'Defaults'}{'Port'}="65467";
	$RequiredArgs{'Defaults'}{'Key'}="123123";

	my %Connector;
	$RCE{"Host"}="$RequiredArgs{'Defaults'}{'Host'}" if (!$RCE{"Host"});
	$RCE{"Port"}="$RequiredArgs{'Defaults'}{'Port'}" if (!$RCE{"Port"});
	$RCE{"Key"}="$RequiredArgs{'Defaults'}{'Key'}" if (!$RCE{"Key"});
	my $rce;
	if (!defined($RCE{'KeyFile'})){
		$rce=RCE->new('ServerAddr'=>$RCE{"Host"}, 'RCEPort'=>$RCE{"Port"}, 'Key'=>$RCE{'Key'});
	} else {
		$rce=RCE->new('ServerAddr'=>$RCE{"Host"}, 'RCEPort'=>$RCE{"Port"}, 'KeyFile'=>$RCE{'KeyFile'});
	}
	if ($rce){
		$RCE{"Connected"}=1;
		$RCE{'Handle'}=$rce;
	} else {
		return undef;
	}
	$RCE{'Type'}="Windows";
	$RCE{'RequiredArgs'}=\%RequiredArgs;

	my $ConnectorObject=\%RCE;
	bless $ConnectorObject, $PKG;
	return $ConnectorObject;
}

sub test {
	my $OBJ=shift();
	my $out=$OBJ->execute("ver");
	if ($out){
		return 1;
	}
	return 0;
}

sub execute {
	my $OBJ=shift();
	my $command=shift();
	my $rce=${$OBJ}{'Handle'};
	my @result;
	my $output=$rce->Execute("$command");
	@result = split /\n/, $output if ($output);
	return @result;
}

sub ServerTime {
	my $OBJ=shift();
	my @result=$OBJ->execute("echo . | date");
	my $date=$result[0];
	$date=substr($date,index($date,"is:")+4,length($date)-(index($date,"is:")+4));
	@result=$OBJ->execute("echo . | time");
	my $time=$result[0];
	$time=substr($time,index($time,"is:")+4,length($time)-(index($time,"is:")+4));
	return "$date$time";
}

sub OS {
	my $OBJ=shift();
	my @result=$OBJ->execute("ver");
	return $result[1];
}

sub Args {
	my $OBJ=shift();
	return %{$$OBJ{'RequiredArgs'}};
}

sub Server {
	my $OBJ=shift();
	my @result=$OBJ->execute("ver");
	return $result[1];
}

sub BaseDir {
	my $OBJ=shift();
	my @result=$OBJ->execute("cd");
	return $result[0];
}

sub Environment {
	my $OBJ=shift();
	my @result=$OBJ->execute("set");
	my %env;
	for my $line (@result){
		next if (!$line);
		my ($var,$val)=split "=", $line;
		$env{$var}=$val;
	}
	return %env;
}

sub disconnect {
	my $OBJ=shift();
	return 0;
}

sub close {
	my $OBJ=shift();
	return disconnect($OBJ);
}

sub register {
	# Gets called at installation time 
	eval {
		require JR::Catalog;
	};
	if ($@){
		print STDERR "Couldn't load JR::Catalog. Didn't register.\n";
		return 0;
	}
	my $reg=Catalog->new;
	if (!$reg->isRegistered("Module"=>"ConnectorNativeMSSQL")){
		return $reg->Register("Type"=>"iShellConnector","Object"=>"NativeMSSQL","Module"=>"ConnectorNativeMSSQL");
	}
	return 0;
}

1;
