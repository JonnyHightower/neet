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

# Ranges.pm

# Port and Address range calculations for Neet
# Jonathan Roach
# October 2009 - Added addressRange object - much faster processing than the old IPRange object.


package PortRange;
# This package implements port range calculations

sub new {
	my $PKG=shift();
	my $incrange=shift();
	my @included;
	my @excluded;
	push @included, $incrange if ($incrange);
	my %range;
	$range{'included'}=\@included;
	$range{'excluded'}=\@excluded;
	$range{'split'}=0;
	my $object=\%range;
	bless $object, $PKG;
	return $object;
}

sub Include {
	my $OBJ=shift();
	my $incrange=shift();
	return 0 if (!$incrange);
	push @{$$OBJ{'included'}}, $incrange;
	return 1;
}

sub Exclude {
	my $OBJ=shift();
	my $excrange=shift();
	return 0 if (!$excrange);
	push @{$$OBJ{'excluded'}}, $excrange;
	return 1;
}

sub ListIncludes {
	my $OBJ=shift();
	return @{$$OBJ{'included'}};
}

sub ListExcludes {
	my $OBJ=shift();
	return @{$$OBJ{'excluded'}};
}

sub SplitRange {
	my $OBJ=shift();
	my $Number=shift();
	if ($Number =~ /^\d+$/ && $Number >2 && $Number < 3000){
		$$OBJ{'split'}=$Number;
	}
	return 1;
}

sub RangeSpec {
	my $OBJ=shift();
	my $SelectRange=shift();
	my @portlist;
	my $min=65535;
	my $max=1;

	for my $range (@{$$OBJ{'included'}}){
		my @srs=split(",",$range);
		for my $sr (@srs){
			my ($s,$f)=split("-",$sr);
			$min=$s if ($s<$min);
			if ($f){
				for (my $a=$s; $a<=$f; $a++){
					$portlist[$a]=1;
					$max=$a if ($a>$max);
				}
			} else {
				$portlist[$s]=1;
				$max=$s if ($s>$max);
			}
		}
	}

	for my $range (@{$$OBJ{'excluded'}}){
		my @srs=split(",",$range);
		for my $sr (@srs){
			my ($s,$f)=split("-",$sr);
			if ($f){
				for (my $a=$s; $a<=$f; $a++){
					$portlist[$a]=0;
				}
			} else {
				$portlist[$s]=0;
	
			}
		}
	}

	if ($$OBJ{'split'} && defined($SelectRange) && ($SelectRange < $$OBJ{'split'})){
		my $span=$max-$min + 1;
		my $chunks=int($span / $$OBJ{'split'});
		if (($chunks * $$OBJ{'split'})>$span){
			$chunks--;
		}
		my $_min=($SelectRange * $chunks)+1 + $SelectRange;
		my $_max=$_min + $chunks;
		# Always make the top-end fit the range - in case the chunk sizes mean that the top end isn't reached.
		if (($SelectRange+1) == $$OBJ{'split'}){
			$_max=$max;
		}

		$min=$_min;
		$max=$_max;
	}

	my $rangespec="";
	my $begin=1;
	my $term=0;
	my $previous;
	for (my $a=$min; $a<=$max; $a++){
		if ($begin && $portlist[$a]){
			$rangespec=$a;
			$previous=$a;
			$begin=0;
		}
		next if ($begin);
		if (!$term && (!$portlist[$a] || $a==$max)){
			if ($previous < ($a - 1)){
				# Terminate current span
				if ($a<$max){
					$rangespec .= "-" . ($a-1);
				} else {
					$rangespec .= "-" . ($a);
					last;
				}
			}
			$term=1;
		}

		if ($term && $portlist[$a]){
			$previous=$a;
			if ("$a" ne "$rangespec"){
				$rangespec .= ",$a";
			}
			$term=0;
		}
	}
	return $rangespec;
}


#**************************************************
#**************************************************

package IPRange;

sub new {
	my $PKG=shift();
	my @ranges;
	my %octets;
	my %range;
	$range{'ranges'}=\@ranges;
	$range{'octets'}=\%octets;
	$range{'index'}=0;
	$range{'maxranges'}=0;
	my $self=\%range;
	bless $self, $PKG;
	return $self;
}

sub Add {
	my $self=shift();
	my $addrange=shift();
	return 0 if (!$addrange);
	push @{$$self{'ranges'}}, $addrange;
	return 1;
}

sub Init {
	my $self=shift();
	$$self{'index'}=0;
	$$self{'numaddresses'}=0;
	for my $range (@{$$self{'ranges'}}){
		my @octets=split "\\.", $range;
		my $octetIndex=0;
		my $size=1;
		for my $octet (@octets){
			if ($octet =~ /-/){
				my ($f,$l);
				($f,$l)=split "-", $octet;
				#print "Octet $octet ($octetIndex) [$range]\n";
				${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'s'}}=$f;
				${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'f'}}=$l;
				$size=$size * (($l-$f)+1);
			} else {
				${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'s'}}=$octet;
				${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'f'}}=$octet;
			}
			${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'pointer'}}=${$$self{'octets'}{$$self{'index'}}{"$octetIndex"}{'s'}};
			$octetIndex++;
		}
		${$$self{'octets'}{$$self{'index'}}{'size'}}=$size;
		$$self{'numaddresses'} += $size;
		$$self{'index'}++;
	}
	$$self{'maxranges'}=$$self{'index'};
	$$self{'index'}=0;
}

sub addressesInRange {
	my $self=shift();
	my $index=shift();
	return ${$$self{'octets'}{$index}{'size'}};
}

sub totalAddresses {
	my $self=shift();
	return $$self{'numaddresses'};
}

sub numRanges {
	my $self=shift();
	return ($#{$$self{'ranges'}})+1;
}

sub GetNextAddress {
	my $self=shift();
	my $ip;
	for (my $a=0; $a<=3; $a++){
		return 0 if (!defined(${$$self{'octets'}{$$self{'index'}}{"$a"}{'pointer'}}));
		$ip .= ${$$self{'octets'}{$$self{'index'}}{"$a"}{'pointer'}};
		$ip .= "." if ($a<3);
	}

	return 0 if ($ip !~ /\d/);

	# Now increment the pointers for next time
	if (${$$self{'octets'}{$$self{'index'}}{'3'}{'pointer'}} < ${$$self{'octets'}{$$self{'index'}}{'3'}{'f'}}){
		# Increment byte 3
		${$$self{'octets'}{$$self{'index'}}{'3'}{'pointer'}}++;
	} else {
		# Byte 3 is at the top of the range. Check byte 2
		if (${$$self{'octets'}{$$self{'index'}}{'2'}{'pointer'}} < ${$$self{'octets'}{$$self{'index'}}{'2'}{'f'}}){
			# Increment byte 2 and reset byte 3
			${$$self{'octets'}{$$self{'index'}}{'2'}{'pointer'}}++;
			${$$self{'octets'}{$$self{'index'}}{'3'}{'pointer'}} = ${$$self{'octets'}{$$self{'index'}}{'3'}{'s'}};
		} else {
			# Byte 2 is at the top of the range. Check byte 1
			if (${$$self{'octets'}{$$self{'index'}}{'1'}{'pointer'}} < ${$$self{'octets'}{$$self{'index'}}{'1'}{'f'}}){
				# Increment byte 1 and reset byte 2
				${$$self{'octets'}{$$self{'index'}}{'1'}{'pointer'}}++;
				${$$self{'octets'}{$$self{'index'}}{'2'}{'pointer'}} = ${$$self{'octets'}{$$self{'index'}}{'2'}{'s'}};
			} else {
				# Byte 1 is at the top of the range. Check byte 0
				if (${$$self{'octets'}{$$self{'index'}}{'0'}{'pointer'}} < ${$$self{'octets'}{$$self{'index'}}{'0'}{'f'}}){
					# Increment byte 0 and reset byte 2
					${$$self{'octets'}{$$self{'index'}}{'0'}{'pointer'}}++;
					${$$self{'octets'}{$$self{'index'}}{'1'}{'pointer'}} = ${$$self{'octets'}{$$self{'index'}}{'1'}{'s'}};
				} else {
					# Check that we're not on the last range
					if ($$self{'index'} < $$self{'maxranges'}){
						# we aren't on the last range yet.
						$$self{'index'}++;
					} else {
						# We are on the last one.
						return 0;
					}
				}
			}
		}
	}
	return $ip;
}

#**************************************************
#**************************************************

package addressRange;

sub new {
	my $self=shift();
	my $range=shift();
	if ($range !~ /^\d{1,3}(-\d{1,3}){0,1}\.\d{1,3}(-\d{1,3}){0,1}\.\d{1,3}(-\d{1,3}){0,1}\.\d{1,3}(-\d{1,3}){0,1}$/){
		return undef;
	}
	my %data;
	my $object=\%data;
	bless $object, $self;
	$data{'range'}=$range;
	@{$data{'octets'}{'values'}}=split "\\.", $range;
	$data{'addresses'}=0;
	$data{'pointer'}=0;
	# Set starts and ends
	for (my $i=0;$i<=3;$i++){
		if (${$data{'octets'}{'values'}}[$i] =~ /-/){
			($data{'octets'}{'limits'}{$i}{'low'},$data{'octets'}{'limits'}{$i}{'high'})=split "-", ${$data{'octets'}{'values'}}[$i];
		} else {
			($data{'octets'}{'limits'}{$i}{'low'},$data{'octets'}{'limits'}{$i}{'high'})=(${$data{'octets'}{'values'}}[$i], ${$data{'octets'}{'values'}}[$i]);
		}
	}

	# Set up the bitmap
	for (my $o0=$data{'octets'}{'limits'}{0}{'low'}; $o0<=$data{'octets'}{'limits'}{0}{'high'}; $o0++){
		for (my $o1=$data{'octets'}{'limits'}{1}{'low'}; $o1<=$data{'octets'}{'limits'}{1}{'high'}; $o1++){
			for (my $o2=$data{'octets'}{'limits'}{2}{'low'}; $o2<=$data{'octets'}{'limits'}{2}{'high'}; $o2++){
				for (my $o3=$data{'octets'}{'limits'}{3}{'low'}; $o3<=$data{'octets'}{'limits'}{3}{'high'}; $o3++){
					${$data{'bitmap'}{$o0}{$o1}{$o2}{$o3}}=1;
					$data{'addresses'}++;
				}
			}
		}
	}
	return $object;
}

sub range {
	my $self=shift();
	return $$self{'range'};
}

sub numAddresses {
	my $self=shift();
	return $$self{'addresses'};

}

sub exclude {
	my $self=shift();
	my $range=shift();
	my %data;
	@{$data{'octets'}{'values'}}=split "\\.", $range;

	# Set starts and ends of octets
	for (my $i=0;$i<=3;$i++){
		#print "${$data{'octets'}{'values'}}[$i]\n";
		if (${$data{'octets'}{'values'}}[$i] =~ /-/){
			($data{'octets'}{'limits'}{$i}{'low'},$data{'octets'}{'limits'}{$i}{'high'})=split "-", ${$data{'octets'}{'values'}}[$i];
		} else {
			($data{'octets'}{'limits'}{$i}{'low'},$data{'octets'}{'limits'}{$i}{'high'})=(${$data{'octets'}{'values'}}[$i], ${$data{'octets'}{'values'}}[$i]);
		}
	}

	# Place changes on the bitmap
	for (my $o0=$data{'octets'}{'limits'}{0}{'low'}; $o0<=$data{'octets'}{'limits'}{0}{'high'}; $o0++){
		for (my $o1=$data{'octets'}{'limits'}{1}{'low'}; $o1<=$data{'octets'}{'limits'}{1}{'high'}; $o1++){
			for (my $o2=$data{'octets'}{'limits'}{2}{'low'}; $o2<=$data{'octets'}{'limits'}{2}{'high'}; $o2++){
				for (my $o3=$data{'octets'}{'limits'}{3}{'low'}; $o3<=$data{'octets'}{'limits'}{3}{'high'}; $o3++){
					if (defined($$self{'bitmap'}{$o0}{$o1}{$o2}{$o3})){
						undef ($$self{'bitmap'}{$o0}{$o1}{$o2}{$o3});
						$$self{'addresses'}--;
					}
				}
			}
		}
	}
}

sub addressList {
	my $self=shift();
	my @list; $#list=-1;
	# Set up the bitmap
	for (my $o0=$$self{'octets'}{'limits'}{0}{'low'}; $o0<=$$self{'octets'}{'limits'}{0}{'high'}; $o0++){
		for (my $o1=$$self{'octets'}{'limits'}{1}{'low'}; $o1<=$$self{'octets'}{'limits'}{1}{'high'}; $o1++){
			for (my $o2=$$self{'octets'}{'limits'}{2}{'low'}; $o2<=$$self{'octets'}{'limits'}{2}{'high'}; $o2++){
				for (my $o3=$$self{'octets'}{'limits'}{3}{'low'}; $o3<=$$self{'octets'}{'limits'}{3}{'high'}; $o3++){
					if (defined($$self{'bitmap'}{$o0}{$o1}{$o2}{$o3})){
						push @list, "$o0.$o1.$o2.$o3";
					}
				}
			}
		}
	}
	$$self{'list'}=\@list;
	return @list;
}

sub getNextAddress {
	my $self=shift();
	my $index=$$self{'pointer'};
	$$self{'pointer'}++;
	return ${$$self{'list'}}[$index];
}

sub reset {
	my $self=shift();
	$$self{'pointer'}=0;
}

1;
