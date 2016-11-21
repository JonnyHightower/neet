#!/usr/bin/perl -w

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
push @INC, ".";
use strict;
use checkdeps;

# This script checks the dependencies prior to the installation of neet
my @locations;

readDependencies();
unlink "dependencyErrors.log";

my (@criticals,@nonrecs,$missing);
my $error=0;

for my $component (listExecutableComponents()){
	my ($result,$path)=checkExecutableComponent($component);
	my ($executable,$fullpath);
	if ($path){
		$executable=getParam($component,"executable");
		$fullpath="$path/$executable";
	}
	if ($result==2){
		push @criticals, $component;
	} elsif ($result==1){
		push @nonrecs, $component;
		push @locations, "$executable=$fullpath\n" if (!isMissing($component));
	} else {
		push @locations, "$executable=$fullpath\n" if (!isMissing($component));

	}
}

for my $c (@nonrecs){
	my $message=getMessage($c,"recommended");
	my $download=getParam($c,"download");
	if ($download){
		$message .= "\n $c can be downloaded from the following URI:\n $download\n";
	}
	if (!isMissing($c)){
		errorLog "*-------------------------------------------------------------------------*\n" .
			  " Dependency \"$c\" version " . actualVersion($c) . " was found, but it really should be at least\n" .
				" version " . recommendedVersion($c) . ".\n\n" . $message .
				"*-------------------------------------------------------------------------*\n\n";
	} else {
		errorLog "*-------------------------------------------------------------------------*\n" .
			  	" Non-critical dependency \"$c\" could not be found.\n\n" . $message .
					"*-------------------------------------------------------------------------*\n\n";
	}
	$error=1;
}
for my $c (@criticals){
	my $message=getMessage($c,"critical");
	if (index($message,"No help text")==1){
		$message=getMessage($c,"recommended");
	}
	my $download=getParam($c,"download");
	if ($download){
		$message .= "\n $c can be downloaded from the following URI:\n $download\n";
	}
	if (!isMissing($c)){
		errorLog "*!!!!---------------------------------------------------------------!!!!*\n" .
			  " Critical dependency: \"$c\", minimum version " . criticalVersion($c) . ", could not be found.\n" .
				" The most recent version which could be found was version " . actualVersion($c) .  ".\n\n" . $message .
				"*-------------------------------------------------------------------------*\n";
	} else {
		errorLog "*!!!!---------------------------------------------------------------!!!!*\n\n" .
			  " Critical missing dependency: \"$c\" could not be found.\n\n" . $message .
				"*-------------------------------------------------------------------------*\n\n";
	}
	$error=2;
}

if ($error < 2){
	unlink "locations";
	if (open(LOC,">locations")){
		print LOC @locations;
		close LOC;
	}
}

# Now check the PERL kit
$#criticals=-1; $#nonrecs=-1;

for my $component (listPerlComponents()){
	my $result=checkPerlComponent($component);
	if (!$result){
		if (getParam($component,"critical")){
			my $message=getMessage($component,"critical");
			if (index($message,"No help text")==1){
				$message=getMessage($component,"recommended");
			}
			errorLog "*!!!!---------------------------------------------------------------!!!!*\n\n" .
			  " Critical missing PERL dependency: \"$component\" could not be found.\n\n" . $message .
				"*-------------------------------------------------------------------------*\n\n";
			$error=2;
		} else {
			my $message=getMessage($component,"recommended");
			errorLog "*-------------------------------------------------------------------------*\n" .
							" Non-critical PERL library dependency \"$component\" could not be found.\n\n" . $message .
							"*-------------------------------------------------------------------------*\n\n";
			$error=1 if ($error==0);
		}
	}
}

exit $error;

