# Dependency checking Perl module
# Dependencies are read from dependencies.conf. Error and advisory messages are
# read from messages.dat.

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

my (@dependencyfile, @messages, %components);
my $missing="defined ";
my $modLoad;

sub readDependencies {
	if ((! -f "dependencies.conf") || (! -f "messages.dat")) {
		criticalDie ("Couldn't find support files");
	}

	if (open(FH,"dependencies.conf")){
		@dependencyfile=<FH>;
		close FH;
	} else {
		criticalDie ("Couldn't read dependencies");
	}
	if (open(FH,"messages.dat")){
		@messages=<FH>;
		close FH;
	} else {
		criticalDie ("Couldn't read messages");
	}
}

sub checkExecutableComponent {
	my $component=shift();
	$components{$component}{'exec'}=getParam($component,"executable");
	$components{$component}{'vercmd'}=getParam($component,"versioncommand");
	$components{$component}{'verfmt'}=getParam($component,"versionformat");
	$components{$component}{'paths'}=getParam($component,"likelypaths");
	$components{$component}{'rec'}=getParam($component,"recommended");
	$components{$component}{'crit'}=getParam($component,"critical");
	$components{$component}{'versions'}=0;
	$components{$component}{'highest'}{'version'}=0;

	# Run through the possible locations for $component, and store the version found in each location.
	my $checked=""; my ($critical,$executed)=(0,0);
	if (paramExists($component,"critical")){
		$critical=1;
	}

	my @paths=split ":", $components{$component}{'paths'};
	push @paths, split ":", $ENV{'PATH'};

	for my $path (@paths){
		# Don't check the same path twice
		next if (index($checked,"$path:")>=0);
		$checked .= "$path:";
		if (!paramExists($component,"versioncommand")){
			if ( -x "${path}"){
				$components{$component}{'versions'}++;
				$components{$component}{'version'}{$components{$component}{'versions'}}{'version'}=1;
				$components{$component}{'version'}{$components{$component}{'versions'}}{'path'}=$path;
				$executed=1;
				return (0,"${path}");
			}
		}
		my $version=getVersion($path,$components{$component}{'exec'},$components{$component}{'vercmd'},$components{$component}{'verfmt'});
		if ($version){
			$executed=1;
			#print "Version at $path/$components{$component}{'exec'} is $version\n";
			$components{$component}{'versions'}++;
			$components{$component}{'version'}{$components{$component}{'versions'}}{'version'}=$version;
			$components{$component}{'version'}{$components{$component}{'versions'}}{'path'}=$path;
		}
	}

	# No point doing further processing if we couldn't execute the version command
	# Return codes: 0=no error; 1=recommended version not found; 2=critically low version not found
	if (!$executed){
		$missing .= "$component ";
		if ($critical){
			return (2,undef);
		} else {
			return (1,undef);
		}
	}

	# Find the highest version available and store its path
	for (my $i=1; $i<=$components{$component}{'versions'}; $i++){
		my $ver=$components{$component}{'version'}{$i}{'version'};
		my $path=$components{$component}{'version'}{$i}{'path'};
		if (!versionMeets($components{$component}{'highest'}{'version'},$ver)){
			$components{$component}{'highest'}{'version'}=$ver;
			$components{$component}{'highest'}{'path'}=$path;
		}
	}

	# Return codes: 0=no error; 1=recommended version not found; 2=critically low version not found
	my $code=0;
	my $path=undef;
	if ($components{$component}{'rec'}){
		# Check that we have the recommended version
		if (versionMeets($components{$component}{'highest'}{'version'},$components{$component}{'rec'})){
			$path=$components{$component}{'highest'}{'path'};
			return ($code,$path);
		} else {
			$code=1;
			if (!$critical){
				$path=$components{$component}{'highest'}{'path'};
				return ($code,$path);	
			}
		}
	}
	if ($critical){
		# Check that we have the critical version
		if (versionMeets($components{$component}{'highest'}{'version'},$components{$component}{'crit'})){
			$path=$components{$component}{'highest'}{'path'};
			return ($code,$path);
		} else {
			$code=2;
		}
	}
	return ($code,$path);
}

sub executable {
	my $component=shift();
	return $components{$component}{'highest'}{'path'} . "/" . $components{$component}{'exec'};
}
sub recommendedVersion {
	my $component=shift();
	return $components{$component}{'rec'};
}
sub criticalVersion {
	my $component=shift();
	return $components{$component}{'crit'};
}
sub actualVersion {
	my $component=shift();
	return $components{$component}{'highest'}{'version'};
}
sub actualVersionPath {
	my $component=shift();
	return $components{$component}{'highest'}{'path'};
}

sub versionMeets {
	# Checks versions to 4 orders
	my $actualversion=shift();
	my $desiredversion=shift();
	my ($avm1,$avm2,$avm3,$avm4)=split "\\.", $actualversion;
	my ($dvm1,$dvm2,$dvm3,$dvm4)=split "\\.", $desiredversion;

	if ($avm1>$dvm1){
		return 1;
	} elsif ($avm1<$dvm1){
		return 0;
	} elsif (defined($dvm2)){
		if (!defined($avm2)){
			$avm2=0;
		}
		#print "Checking minor\n";
		if ($avm2>$dvm2){
			return 1;
		} elsif ($avm2<$dvm2){
			return 0;
		} elsif (defined($dvm3)){
			if (!defined($avm3)){
				$avm3=0;
			}
			#print "Checking minor minor\n";
			if ($avm3>$dvm3){
				return 1;
			} elsif ($avm3<$dvm3){
				return 0;
			} elsif (defined($dvm4)){
				if (!defined($avm4)){
					$avm4=0;
				}
				#print "Checking minor minor minor\n";
				if ($avm4>$dvm4){
					return 1;
				} elsif ($avm4<$dvm4){
					return 0;sub modFailed {
	$modFail=1;
}
				} else {
					return 1;
				}
			} else {
				return 1; #$dvm4 wasn't defined
			}
		} else {
			return 1; #$dvm3 wasn't defined
		}
	} else {
		return 1; # $dvm2 wasn't defined
	}
	return 0;
}

sub getVersion {
	my $path=shift();
	my $exec=shift();
	my $command="$path/" . shift();
	my $format=shift();
	$exec="$path/$exec";
	if (! -x "$exec"){
		return undef;
	}
	my @result=`${command}`;
	for my $line (@result){
		if ($line =~ /$format/){
			$line =~ s/^[\S\s]+($format)[\S\s]+$/$1/;
			return $line;
		}
	}
}

sub listExecutableComponents {
	my @c;
	for my $l (@dependencyfile){
		my $line=$l;
		if ($line =~ /^component: /){
			chomp $line; $line =~ s/^component: //;
			if (paramExists($line,"executable")){
				push @c, $line;
			}
		}
	}
	return @c;
}

sub getParam {
	my $component=shift();
	my $parameter=shift();
	my $collect=0;
	for my $l (@dependencyfile){
		my $line = $l;
		if ($line =~ /^component: $component\n/){
			$collect=1; next;
		}
		if ($collect && (index($line,"$parameter: ")==0)){
			chomp $line; my ($junk,$line) = split (": ", $line, 2);
			return $line;
		}
		if ($collect && (index($line,"component: ")==0)){
			return undef;
		}
	}
}

sub paramExists {
	my $component=shift();
	my $parameter=shift();
	my $collect=0;
	for my $l (@dependencyfile){
		my $line = $l;
		if ($line =~ /^component: $component\n/){
			$collect=1; next;
		}
		if ($collect && (index($line,"$parameter: ")==0)){
			return 1;
		}
		if ($collect && (index($line,"component: ")==0)){
			return undef;
		}
	}
	return 0;
}

sub getMessage {
	my $component=shift();
	my $type=shift();
	my $message;
	my $collect=0;
	for my $l (@messages){
		my $line = $l;
		if ($line =~ /^::$component:$type\n/){
				$collect=1;
				next;
		}
		if ($collect){
			if ($line =~ /^::/){
				$collect=0;
				last;
			}
			$message .= $line if ($line =~ /\S/);
		}
	}
	if (!$message){
		$message=" No help text is available for dependency $component.\n";
	}
	return $message;
}

sub isMissing {
	my $component=shift();
	if (index($missing,"$component ")>=0){
		return 1;
	}
	return 0;
}

sub listPerlComponents {
	my @c;
	for my $l (@dependencyfile){
		my $line=$l;
		if ($line =~ /^component: /){
			chomp $line; $line =~ s/^component: //;
			if (paramExists($line,"perlmodule")){
				push @c, $line;
			}
		}
	}
	return @c;
}

sub checkPerlComponent {
	my $component=shift();
	$components{$component}{'perlmodule'}=getParam($component,"perlmodule");
	$components{$component}{'rec'}=paramExists($component,"recommended");
	$components{$component}{'crit'}=paramExists($component,"critical");
	$modLoad=1;
	$components{$component}{'test'}=testPerlModule($components{$component}{'perlmodule'});
	return $components{$component}{'test'};
}

sub testPerlModule {
	my $module=shift();
	if ($module !~ /\.pm$/){
		$module .= ".pm";
	}
	$module =~ s/::/\//g;
	eval {
		require "$module";
	} || _modFailed();
	return $modLoad;
}

sub _modFailed {
	$modLoad=0;
}

sub errorLog {
	my $m=shift();
	open (FH,">>dependencyErrors.log");
	print FH "$m";
	close FH;
	print $m;
}

sub criticalDie {
	my $m=shift();
	errorLog($m);
	exit 2;
}


1;

