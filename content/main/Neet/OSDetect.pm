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

#OSDetect.pm

package Neet::OSDetect;

sub new {
	my $pkg=shift();
	my $file=shift();
	# Store the signatures in memory - cut down on disk accesses
	my (%OSD,@Sigs);
	if (open(FH,$file)){
		until (eof FH){
			my $line = readline(*FH);
			if ($line =~ /^\s/){
				$line =~ s/^\s+//g;
			}
			if (($line =~ /^\#/) || ($line !~ /\w/) || ($line !~ /\*/)) {
				next;
			}
			chomp $line;
			push @Sigs, "$line";
		}
		close FH;
	} else {
		return undef;
	}
	$OSD{'Sigs'}=\@Sigs;
	my $self = \%OSD;
	bless $self, $pkg;
	return $self;
}

sub BannerToOS {
	my $self=shift();
	my $service=shift();
	my $banner=shift();
	if (!defined($banner)){
		return undef;
	}
	$banner =~ s/\W//g;
	my ($type,$family,$famconf,$version,$verconf,$servicepack,$spconf);
	my $c=0;

	# Work out the OS family first
	for my $sig (@{$$self{'Sigs'}}){
		next if ($sig !~ /^$service\*/);
		my ($s,$b,$ty,$fa,$fc,$ve,$vc,$sp,$sc)=split ("\\*", $sig);
		$b =~ s/\W//g;
		next if ($banner !~ /$b/);
		($s,$b)=("","");
		if ($fc && ($fc > $c)){
			$family=$fa;
			$type=$ty;
			$famconf=$fc;
			$c=$fc;
		}
	}

	return undef if (!$type);

	# Work out the version next
	if ($family){
		$c=0;
		for my $sig (@{$$self{'Sigs'}}){
			next if ($sig !~ /^$service\*/);
			my ($s,$b,$ty,$fa,$fc,$ve,$vc,$sp,$sc)=split ("\\*", $sig);
			next if ("$fa" ne "$family");
			$b =~ s/\W//g;
			next if ($banner !~ /$b/);
			($s,$b)=("","");
			if ($vc && ($vc > $c)){
				$version=$ve;
				$verconf=$vc;
				$c=$vc;
			}
		}
	}

	# Work out the service pack next
	if ($version){
		$c=0;
		for my $sig (@{$$self{'Sigs'}}){
			next if ($sig !~ /^$service\*/);
			my ($s,$b,$ty,$fa,$fc,$ve,$vc,$sp,$sc)=split ("\\*", $sig);
			next if ("$fa" ne "$family") || ("$ve" ne "$version");
			$b =~ s/\W//g;
			next if ($banner !~ /$b/);
			($s,$b)=("","");
			if ($sc && ($sc > $c)){
				$servicepack=$sp;
				$spconf=$sc;
				$c=$sc;
			}
		}
	}

	return ($type,$family,$famconf,$version,$verconf,$servicepack,$spconf);
}

sub HashToOS {
	my $self=shift();
	my $hash=shift();
	my ($type,$family,$fconf,$version,$vconf,$servicepack,$sconf,%sort,@values);

	# Add up the scores and determine OS family first
	for (my $i=0; $i< $$hash{'index'}{'0'}; $i++){
		my ($_type,$_family,$_fconf);
		$_type=$$hash{$i}{'type'}; $_family=$$hash{$i}{'family'}; $_fconf=$$hash{$i}{'fconf'};
		#print "Type $_type Fam $_family Confidence $_fconf\n";
		if ($$sort{$_family}{'c'}){
			$$sort{$_family}{'c'} += $_fconf;
		} else {
			$$sort{$_family}{'c'} = $_fconf;
			$$sort{$_family}{'t'} = $_type;
			push @values, $_family;
		}
	}
	#print "Sorting Family\n";
	my $c=0;
	for my $fam (@values){
		#print "$fam (" . $$sort{$fam}{'t'} . ") " . $$sort{$fam}{'c'} . "\n";
		if ($$sort{$fam}{'c'} > $c){
			$family=$fam;
			$type=$$sort{$fam}{'t'};
			$fconf=$$sort{$fam}{'c'};
			$c=$$sort{$fam}{'c'};
		}
	}

	return undef if (!$family);
	#print "Chosen $family\n";

	# Now choose the version
	$#values=-1; %sort=();
	for (my $i=0; $i< $$hash{'index'}{'0'}; $i++){
		my ($_family,$_version,$_vconf);
		$_family=$$hash{$i}{'family'}; $_version=$$hash{$i}{'version'}; $_vconf=$$hash{$i}{'vconf'};
		next if ((!$_version) || ("$_family" ne "$family"));
		#print "Fam $_family Ver $_version Confidence $_vconf\n";
		if ($$sort{$_version}{'c'}){
			$$sort{$_version}{'c'} += $_vconf;
		} else {
			$$sort{$_version}{'c'} = $_vconf;
			push @values, $_version;
		}
	}
	#print "Sorting Version\n";
	$c=0;
	for my $ver (@values){
		#print "$ver " . $$sort{$ver}{'c'} . "\n";
		if ($$sort{$ver}{'c'} > $c){
			$version=$ver;
			$vconf=$$sort{$ver}{'c'};
			$c=$$sort{$ver}{'c'};
		}
	}

	if ($version){
		#print "Chosen $version\n";
		# Now choose the service pack
		$#values=-1; %sort=();
		for (my $i=0; $i< $$hash{'index'}{'0'}; $i++){
			my ($_family,$_version,$_servicepack,$_sconf);
			$_family=$$hash{$i}{'family'}; $_version=$$hash{$i}{'version'}; $_servicepack=$$hash{$i}{'servicepack'}; $_sconf=$$hash{$i}{'sconf'};
			next if ((!$_servicepack) || ("$_version" ne "$version") || ("$_family" ne "$family"));
			#print "Fam $_family Ver $_version ServicePack $_servicepack Confidence $_sconf\n";
			if ($$sort{$_servicepack}{'c'}){
				$$sort{$_servicepack}{'c'} += $_sconf;
			} else {
				$$sort{$_servicepack}{'c'} = $_sconf;
				push @values, $_servicepack;
			}
		}
		#print "Sorting ServicePack\n";
		$c=0;
		for my $sp (@values){
			#print "$sp " . $$sort{$sp}{'c'} . "\n";
			if ($$sort{$sp}{'c'} > $c){
				$servicepack=$sp;
				$sconf=$$sort{$sp}{'c'};
				$c=$$sort{$sp}{'c'};
			}
		}
		#print "Chosen $servicepack\n";
	}
	return ($type,$family,$fconf,$version,$vconf,$servicepack,$sconf);
}

sub Unload {
	my $self=shift();
	$#{$self{'Sigs'}}=-1;
	return undef;
}


1;
