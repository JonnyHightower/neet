##########################################################################
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

# JR::OutputIsolator.pm

# Jonathan Roach

use strict;

package JR::iShell::OutputIsolator;


sub new {
	my $PKG=shift();
	my (@HTML,@Tokens,$SHTML,%HTMLObj);
	my @Containers=("html","head","title","body","table","td","tr","div","pre");
	$HTMLObj{'Raw'}=\@HTML;
	$HTMLObj{'Tokens'}=\@Tokens;
	$HTMLObj{'Page'}=\$SHTML;
	$HTMLObj{'Calibrated'}=0;
	$HTMLObj{'Index'}=0;
	$HTMLObj{'Containers'}=\@Containers;
	my $Object=\%HTMLObj;
	bless $Object, $PKG;
	return $Object;
}

sub LoadPage {
	my $obj=shift();
	my $serial;
	@{$$obj{'Raw'}}=(@_);
	for my $line (@{$$obj{'Raw'}}){
		$serial .= $line if ($line);
	}
	$$obj{'Page'}=$serial;
}

sub Calibrate {
	my $obj=shift();
	my $string=lc(shift());
	my $lcpage=lc($$obj{'Page'});
	if ($lcpage !~ /$string/){
		$obj->FlushPage;
		die ("****CANNOT CALIBRATE ****\n$lcpage\n****CANNOT CALIBRATE ****\n" .
			"The required output string was not found in the returned HTML\n");
	}
	$obj->_SerialisedTokenise($lcpage);
	for my $token (@{$$obj{'Tokens'}}){
		last if ("$token" eq "$string");
		for my $cont (@{$$obj{'Containers'}}){
			if ($token =~ /<$cont[\s>]/){
				$$obj{'Index'}++;
				last;
			}
		}
	}

	$obj->isCalibrated(1) if ($$obj{'Index'} > 0);
	$obj->FlushPage;
}

sub FlushPage {
	my $obj=shift();
	@{$$obj{'Tokens'}}=();
	@{$$obj{'Raw'}}=();
	$$obj{'Page'}="";
	return 1;
}

sub GetOutput {
	my $obj=shift();
	return undef if (!$$obj{'Page'});
	$obj->_SerialisedTokenise($$obj{'Page'});
	my $count=0; my $tkindex=0;
	for my $token (@{$$obj{'Tokens'}}){
		if ($token =~ /Directory of/){
			# This is one with NO HTML. Let's get out of here
			$token =~ s/\r//g;
			my @out= split "\\n", $token;
			$obj->FlushPage;
			return @out;
		}
		for my $cont (@{$$obj{'Containers'}}){
			if (lc($token) =~ /<$cont[\s>]/){
				$count++;
				last;
			}
		}
		last if ($count == $$obj{'Index'});
		$tkindex++;
	}

	return $$obj{'Page'} if (!$tkindex);
	return ("") if (!${$$obj{'Tokens'}}[$tkindex+1] || $obj->isClosingTag(${$$obj{'Tokens'}}[$tkindex+1]) || (${$$obj{'Tokens'}}[$tkindex+1] !~ /\S/));
	${$$obj{'Tokens'}}[$tkindex+1] =~ s/\r//g;
	my @out= split "\\n", ${$$obj{'Tokens'}}[$tkindex+1];
	$obj->FlushPage;
	return @out;
}


sub isClosingTag {
	my $obj=shift();
	my $tag=shift();
	my $is=0;
	for my $cont (@{$$obj{'Containers'}}){
		if (lc($tag) =~ /<\/$cont[\s>]/){
			$is=1;
			last;
		}
	}
	return $is;
}

sub _SerialisedTokenise {
	my $obj=shift();
	my $html=shift();
	@{$$obj{'Tokens'}}=();
	my $current;
	for (my $a=0; $a < length($html); $a++){
		my $c=substr($html,$a,1);
		if ("$c" eq "<"){
			if ($current){
				push @{$$obj{'Tokens'}}, $current;
				$current="";
			}
		}
		if ("$c" eq ">"){
			$current .= $c;
			push @{$$obj{'Tokens'}}, $current;
			$current="";
			next;
		}
		$current .= $c;
		if ($a > 20 && $current && $current =~ /Directory of/){
			@{$$obj{'Tokens'}}=();
			push @{$$obj{'Tokens'}}, $html;
			last;
		}
	}
}

sub isCalibrated {
	my $Obj=shift();
	my $newval=shift();
	if ($newval){
		$$Obj{'Calibrated'}=1;
		return 1;
	} else {
		return $$Obj{'Calibrated'};
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
	if (!$reg->isRegistered("Module"=>"OutputIsolator")){
		return $reg->Register("Type"=>"OutputIsolator","Object"=>"OutputIsolator","Module"=>"OutputIsolator");
	}
	return 0;
}

1;
