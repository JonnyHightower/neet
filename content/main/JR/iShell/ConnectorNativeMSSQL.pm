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

# JR::ConnectorNativeMSSQL.pm

# This is the "Native MSSQL" connector for the ishell command shell framework.
# Jonathan Roach

# It uses DBI, DBD::Sybase and FreeTDS to provide
# access to MS-SQL via the TDS protocol (a la TCP/1433 access).

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

package JR::iShell::ConnectorNativeMSSQL;
use DBI;

sub new {
	my $PKG=shift();
	my %SQLServer=@_;
	my %RequiredArgs;
	$RequiredArgs{'Args'}="Host Port User Pass";
	$RequiredArgs{'Optional'}="Host Port User Pass";
	$RequiredArgs{'Mandatory'}="";
	$RequiredArgs{'Defaults'}{'Host'}="127.0.0.1";
	$RequiredArgs{'Defaults'}{'Port'}="1433";
	$RequiredArgs{'Defaults'}{'User'}="sa";
	$RequiredArgs{'Defaults'}{'Pass'}="";

	my %Connector;
	$SQLServer{"Host"}="$RequiredArgs{'Defaults'}{'Host'}" if (!$SQLServer{"Host"});
	$SQLServer{"Port"}="$RequiredArgs{'Defaults'}{'Port'}" if (!$SQLServer{"Port"});
	$SQLServer{"User"}="$RequiredArgs{'Defaults'}{'User'}" if (!$SQLServer{"User"});
	$SQLServer{"Pass"}="$RequiredArgs{'Defaults'}{'Pass'}" if (!$SQLServer{"Pass"});
	my $server = "dbi:Sybase:server=" . $SQLServer{'Host'} . ":" . $SQLServer{'Port'};

	my $dbh = DBI->connect($server,$SQLServer{'User'},$SQLServer{'Pass'});
	if ($dbh){
		$SQLServer{"Handle"}=$dbh;
		$SQLServer{"Connected"}=1;
	} else {
		return undef;
	}
	$SQLServer{'Type'}="Windows";
	$SQLServer{'RequiredArgs'}=\%RequiredArgs;

	my $ConnectorObject=\%SQLServer;
	bless $ConnectorObject, $PKG;
	return $ConnectorObject;
}

sub test {
	my $OBJ=shift();
	my @res=$OBJ->execute("ver");
	if ($#res <0){
		return 0;
	}
	return 1;	
}

sub runsql {
	my $OBJ=shift();
	my $sql=shift();
	my $dbh=${$OBJ}{'Handle'};
	my @result;
	my $sth = $dbh->prepare("$sql");
	my $rv = $sth->execute;
	my @tmpresults;
	while (@tmpresults=$sth->fetchrow_array){
		for my $row (@tmpresults){
			if ($row){
				push @result, $row;
			} else {
				push @result, "";
			}
		}
	}
	$sth->finish;
	return @result;
}


sub execute {
	my $OBJ=shift();
	my $command=shift();
	my $dbh=${$OBJ}{'Handle'};
	my @result;
	$command =~ s/\]/\]\]/g;
	my $sth = $dbh->prepare("EXEC master..xp_cmdshell [$command]");
	my $rv = $sth->execute;
	my @tmpresults;
	while (@tmpresults=$sth->fetchrow_array){
		for my $row (@tmpresults){
			if ($row){
				push @result, $row;
			} else {
				push @result, "";
			}
		}
	}
	$sth->finish;
	return @result;
}

sub ServerTime {
	my $OBJ=shift();
	my @result=$OBJ->execute("date");
	my $date=$result[0];
	$date=substr($date,index($date,"is:")+4,length($date)-(index($date,"is:")+4));
	@result=$OBJ->execute("time");
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
	my $dbh=${$OBJ}{'Handle'};
	my @result;
	my $sth = $dbh->prepare("select @\@version");
	my $rv = $sth->execute;
	my @tmpresults;
	while (@tmpresults=$sth->fetchrow_array){
		for my $row (@tmpresults){
			if ($row){
				push @result, $row;
			} else {
				push @result, "";
			}
		}
	}
	$sth->finish;
	return $result[0];
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
	my $dbh=${$OBJ}{'Handle'};
	return $dbh->disconnect;
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
