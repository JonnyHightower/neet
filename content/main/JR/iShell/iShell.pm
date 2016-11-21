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

# JR::iShell::iShell.pm

# This is the core module of the iShell command shell framework.
# Jonathan Roach

# It provides an interactive shell object for execution vectors that are not
# session based. For example, xp_cmdshell command execution is not session
# based - each call to xp_cmdshell is completely seperate from the previous call
# and the only environment each instance has is the one inherited from SQL
# server.

# An iShell object is an instance of a set of parameters normally maintained
# through the execution time of a shell - environment variables, command history,
# working directory - that sort of thing.

# Each iShell instance needs to communicate with the command executor via a
# connector. The connectors are PERL modules, and each has a name.
# For example, for the MSSQL server over TDS, you'll need the
# JR::ConnectorNativeMSSQL PERL module, and you'll need to tell your iShell
# instance that this is the connector you want to use.

package JR::iShell::iShell;

sub new {
	# Create a new iShell object
	my $PKG=shift();

	# Process arguments to see which ones to pass through to the connector
	my (@ObjectArgs,@ConnectorArgs);
	while (@_){
		my $testarg=shift(@_);
		if (_isObjArg($testarg)){
			push @ObjectArgs, $testarg;
			push @ObjectArgs, shift(@_);			
		} else {
			push @ConnectorArgs, $testarg;
			push @ConnectorArgs, shift(@_);
		}
	}
	my %ShellParam=@ObjectArgs;
	my %ConnectorParam=@ConnectorArgs;
	my %Shell;

	if (defined($ShellParam{'Verbose'})){
		$Shell{'Verbose'}=$ShellParam{'Verbose'};
	} else {
		$Shell{'Verbose'}=1;
	}

	my $ConnectorType=$ShellParam{'Connector'};
	my $ConnectorName="JR::iShell::Connector" . $ConnectorType;
	# Try and load the connector
	{
	  use JR::Ptools; my $phlux=JR::Ptools->new;
	  #my $_ConnectorPath="JR/" . $ConnectorName . ".pm";
	  my $_ConnectorPath=$phlux->FullPath("$ConnectorName");
	  eval {
		require $_ConnectorPath;
	  };
	  if ($@){
		die "Error loading $ConnectorType connector.\n$@";
	  }
	}

	# OK, we've loaded the connector
	$Shell{'ConnectorName'}=$ConnectorName;
	$Shell{'ConnectorType'}=$ConnectorType;
	print "$ConnectorType connector loaded OK\n" if ($Shell{'Verbose'});

	my $Connector=$ConnectorName->new(@ConnectorArgs);
	if (!$Connector){
		print "Couldn't connect with this connector\n" if ($Shell{'Verbose'});
		return undef;
	}
	# Got the connection. Test it.
	if (!$Connector->test){
		return undef;
	}	

	# Hash to store our shell builtins (these will be processed locally)
	my (%Builtins,%ShellExtensions);
	$Builtins{"cd"}="builtin_cd";
	$Builtins{"exit"}="builtin_quit";
	$Builtins{"quit"}="builtin_quit";
	$Builtins{"retr"}="builtin_retr";
	$Builtins{"put"}="builtin_put";
	$Builtins{"set"}="builtin_set";

	# Set some base values that won't change through the session
	$Shell{'Connector'}=$Connector;
	$Shell{'Params'}=\%ShellParam;
	$Shell{'OS'}=$Connector->OS;
	$Shell{'Basedir'}=$Connector->BaseDir;
	$Shell{'ConnectedAt'}=$Connector->ServerTime;
	$Shell{'Builtins'}=\%Builtins;
	$Shell{'ShellExtensions'}=\%ShellExtensions;

	if ($Shell{'OS'} =~ /Windows/){
		$Shell{'Windows'}=1;
	}

	# Load the base environment
	my %BaseEnv=$Connector->Environment;
	$Shell{'BaseEnv'}=\%BaseEnv;

	# Some OS dependant stuff
	if ($Shell{'Windows'}){
		$Shell{'Prompt'}=">";
		$Shell{'IFS'}="\\";
		$Shell{'EOL'}="\r\n";
		$Builtins{"ls"}="builtin_ls";
		$Builtins{"cat"}="builtin_cat";
	} else {
		$Shell{'Prompt'}="#";
		$Shell{'IFS'}="/";
		$Shell{'EOL'}="\n";
	}

	# Now the persistence. These will change throughout the session
	my (@CommandHistory,@CommandOutput,%EnvVars);
	$Shell{'PWD'}=$Shell{'Basedir'};
	$Shell{'CMDHist'}=\@CommandHistory;
	$Shell{'CMDindx'}=-1;
	$Shell{'EnvVars'}=\%EnvVars;
	$Shell{'Output'}=\@CommandOutput;


	$Shell{'FileServer'}="127.0.0.1";
	$Shell{'Clean'}=1;

	# Now we've created and partially filled the data structures,
	# finally, do the PERL object stuff
	my $iShell=\%Shell;
	bless $iShell, $PKG;
	return $iShell;
}

#== System ==#
sub prompt {
	my $Shell=shift();
	my $PWD=$$Shell{"PWD"};
	my $END=$$Shell{"Prompt"};
	if ($$Shell{"Exit"}){
		return undef;
	}
	print $PWD . $END;
	return $PWD . $END;
}

sub exec {
	my $Shell=shift();
	my $PWD=$$Shell{"PWD"};
	my $command=shift();
	$command =~ s/^\s+//g;
	push @{$Shell{'CMDHist'}}, "$command";
	$$Shell{'CMDindx'}++;

	# Now do the environment application
	$command=$Shell->ApplyEnvironment($command);

	# Trap builtins
	if (my $handler=$Shell->isBuiltin($command)){
		@{$Shell{'Output'}}=();	
		return $Shell->$handler($command);
	}
	if (my $handler=$Shell->isShellExtension($command)){
		@{$Shell{'Output'}}=();
		return $Shell->$handler($command);
	}

	#print "Executing $command";
	$command = "cd $PWD && " . $command;
	@{$Shell{'Output'}}=$$Shell{'Connector'}->execute("$command");
}

sub rawexec {
	my $Shell=shift();
	my $PWD=$$Shell{"PWD"};
	my $command=shift();
	$command =~ s/^\s+//g;
	$command = "cd $PWD && " . $command;
	@{$Shell{'Output'}}=$$Shell{'Connector'}->execute("$command");
}

sub output {
	my $Shell=shift();
	return @{$Shell{'Output'}};
}

sub flush {
	my $Shell=shift();
	@{$Shell{'Output'}}=();
}

#== File System Traversal ==#
sub pwd {
	my $Shell=shift();
	return ${$Shell}{"PWD"};
}

#== System Parameters ==#
sub OS {
	my $Shell=shift();
	return $$Shell{'OS'};
}

sub ServerTime {
	my $Shell=shift();
	return $$Shell{'Connector'}->ServerTime;
}

sub Server {
	my $Shell=shift();
	return $$Shell{'Connector'}->Server;
}

#== Connector Functions ==#

sub _ObjectArgs {
	return (
		"Connector",
		"Verbose"
	);
}
sub _isObjArg {
	my $arg=shift();
	my $is=0;
	for my $a (_ObjectArgs){
		if ("$a" eq "$arg"){
			$is=1;
			last;
		}
	}
	return $is;
}

#========================================#

sub SetEnv {
	my $Shell=shift();
	my $var=shift();
	my $val=shift();
	${$$Shell{'EnvVars'}}{"$var"}=$val;
}

sub UnSetEnv {
	my $Shell=shift();
	my $var=shift();
	${$$Shell{'EnvVars'}}{"$var"}=undef;
}

sub GetEnv {
	my $Shell=shift();
	my $var=shift();
	return ${$$Shell{'EnvVars'}}{"$var"};
}

sub ListEnv {
	my $Shell=shift();
	my @envs;
	for my $a (keys(%{$$Shell{'EnvVars'}})){
		push @envs, $a;
	}
	return @envs;
}

sub ApplyEnvironment {
	my $Shell=shift();
	my $string=shift();
	my @envvars=$Shell->ListEnv;

	for my $envvar (@envvars){
		if ($string =~ /%$envvar%/){
			# Replace all instances of env vars
			my $val=$Shell->GetEnv($envvar);
			$string =~ s/\%$envvar%/$val/g;
		}
	}
	return $string;
}


#========================================#
# Shell Builtins that should be processed 
# here before being passed to the command
# interpreter

# The commands that are trapped and handled
# here are defined in the %Builtins hash within
# the new() method. The keys of the hash are
# the commands to trap, and their values are
# the functions to call on encountering those
# commands.

sub AddShellExtension {
	my $Shell=shift();
	my %NewExtensions=@_;
	my $added=0;
	for my $new (keys(%NewExtensions)){
		$$Shell{'ShellExtensions'}{$new}="main::" . $NewExtensions{$new};
		$added++;
	}
	return $added;
}

sub DeleteShellExtension {
	my $Shell=shift();
	my $Extension=shift();
	$$Shell{'ShellExtensions'}{$Extension}=undef;
	return 1;
}

sub DeleteBuiltin {
	my $Shell=shift();
	my $Builtin=shift();
	$$Shell{'Builtins'}{$Builtin}=undef;
	return 1;
}

sub SystemBuiltins {
	my $Shell=shift();
	return keys (%{$$Shell{'Builtins'}});
}

sub ShellExtensions {
	my $Shell=shift();
	return keys (%{$$Shell{'ShellExtensions'}});
}

sub isBuiltin {
	my $Shell=shift();
	my $command=shift();
	for my $builtin ($Shell->SystemBuiltins) {
		if ($command =~ /^$builtin\s/){
			return ${$$Shell{'Builtins'}}{$builtin};
		} 
	}
	return 0;
}

sub isShellExtension {
	my $Shell=shift();
	my $command=shift();
	for my $extension ($Shell->ShellExtensions) {
		if ($command =~ /^$extension\s/){
			return ${$$Shell{'ShellExtensions'}}{$extension};
		} 
	}
	return 0;
}

sub builtin_cd {
	my $Shell=shift();
	my $command=shift();
	my ($junk,@ChangeTo)=split "\\s", $command;
	my $ChangeToDir=join " ", @ChangeTo;
	my $CurrentDir=$$Shell{'PWD'};
	if ($Shell->OS =~ /Windows/){
		# Windows
		# Allow for forward slashes too
		$ChangeToDir =~ s/\//\\/g;
		my @test=$$Shell{'Connector'}->execute("cd $CurrentDir && cd $ChangeToDir && cd");
		for my $line (@test){
			next if (!$line);
			if (($line =~ /The system cannot find the path specified./) ||
				($line =~ /The directory name is invalid/)){
				print $line;
				return 0;
			} elsif ($line =~ /^\w:\\/){
				$$Shell{'PWD'}=$line;
				last;
			}
		}
	} else {
		# Unix
		my @test=$$Shell{'Connector'}->execute("cd $CurrentDir && cd $ChangeToDir && pwd");
		for my $line (@test){
			next if (!$line);
			if (($line =~ /No such file or directory/)){
				print $line;
				return 0;
			} elsif ($line =~ /^\//){
				$$Shell{'PWD'}=$line;
				last;
			}
		}
	}
}

sub builtin_quit {
	my $Shell=shift();
	$$Shell{'Connector'}->disconnect;
	$$Shell{'Exit'}=1;
}

sub builtin_retr {
	my $Shell=shift();
	my $command=shift();
	my $IFS=$$Shell{'IFS'};
	my ($cmd,$file)=split " ", $command;
	$command= " " . $command;
	if ($$Shell{'Windows'}){
		$command =~ s/ retr / type /;
	} else {
		$command =~ s/ retr / cat /;
	}
	$command =~ s/^ //;
	$Shell->exec($command);

	my $basename;
	if (($$Shell{'Windows'} && $file !~ /$IFS$IFS/) || ((!$$Shell{'Windows'}) && $file !~ /$IFS/)){
		$basename=$file;
	} else {
		$basename=substr($file,rindex($file,"$IFS")+1,length($file)-(rindex($file,"$IFS")+1));
	}
	if (open(FH,">$basename")){
		my @output=$Shell->output;
		for my $line (@output){
			print FH "$line\n";
		}
		close FH;
		print "Saved $file to local file: $basename\n";
	} else {
		print "Couldn't write to $basename!\n";
	}
	$Shell->flush;
	
}

sub builtin_put {
	my $Shell=shift();
	my $command=shift();
	my ($cmd,$local,$remote)=split " ", $command;
	return undef if (!$local);
	$remote=$local if (!$remote);
	if ($$Shell{'Windows'}){
		my @file;
		if (open(PUT,"$local")){
			@file=<PUT>;
			close PUT;
			my $i=0;
			my $error=1;
			for my $line (@file){
				$line =~ s/[\r\n]//g;
				my $dot="";
				if (!length($line) || ($line !~ /\S/)){
					$dot = ".";
				}
				my $extralength=length($remote) + 9;
				if (length($line)>(128 - $extralength)){
					my $a = rindex($line," ");
					my $line1=substr($line,0,$a);
					my $line2=substr($line,$a,length($line)-$a);
					dothebiz($Shell,$line1,$remote,$dot,$i);
					dothebiz($Shell,$line2,$remote,$dot,$i);
				} else {
					dothebiz($Shell,$line,$remote,$dot,$i);
				}
				$i++;
			}
			print "Sent.\n";
		} else {
			print "Couldn't read local file $local.\n";
		}

		sub dothebiz {
			my $Shell=shift();
			my $line=shift();
			my $remote=shift();
			my $dot=shift();
			my $i=shift();
			if (!$i){
				$Shell->rawexec("echo$dot $line > $remote\n");
			} else {
				$Shell->rawexec("echo$dot $line >> $remote\n");
			}
		}
	}
}

sub builtin_ls {
	# Only called on Windows
	my $Shell=shift();
	my $command= " " . shift();
	my $PWD=$$Shell{"PWD"};
	$command =~ s/\sls\s/ dir /g;
	$command =~ s/^\s//;
	$command = "cd $PWD && " . $command;
	@{$Shell{'Output'}}=$$Shell{'Connector'}->execute("$command");
}

sub builtin_cat {
	# Only called on Windows
	my $Shell=shift();
	my $command= " " . shift();
	my $PWD=$$Shell{"PWD"};

	$command =~ s/\scat\s/ type /g;
	$command =~ s/^\s//;
	$command = "cd $PWD && " . $command;
	@{$Shell{'Output'}}=$$Shell{'Connector'}->execute("$command");
}

sub builtin_set {
	my $Shell=shift();
	my $command=shift();
	my $PWD=$$Shell{'PWD'};
	if ($command =~ /^set \w+=\w/){
		my $env=substr($command,4,length($command)-4);
		my ($var,$val)=split "=", $env;
		$Shell->SetEnv($var,$val);
	} else {
		$command = "cd $PWD && " . $command;
		@{$Shell{'Output'}}=$$Shell{'Connector'}->execute("$command");		
	}
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
	if (!$reg->isRegistered("Module"=>"iShell")){
		return $reg->Register("Type"=>"iShellObject","Object"=>"iShell","Module"=>"iShell");
	}
	return 0;
}

1;
