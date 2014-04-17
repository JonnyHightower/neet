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

# API.pm

# This PERL module implements the Neet API which was introduced in Neet version 0.7.0.

package Neet::API;

use Fcntl ':flock';

sub new {
	my $pkg=shift();
	my %internal;
	my $resultsDir=shift();
	$internal{'Log'}=shift();
	$internal{'Config'}=shift();
	my $controlDir=shift();
	return undef if (!defined($resultsDir) || ! -d "$resultsDir");
	if (!defined($controlDir) || ! -d "${resultsDir}/${controlDir}"){
		$controlDir=".neet";
	}
	$internal{'Results'}=$resultsDir;
	$internal{'Control'}=$controlDir;
	my $self = \%internal;
	bless $self, $pkg;
	return $self;
}

sub dirResults {
	my $self=shift();
	return $$self{'Results'};
}

sub dirControl {
	my $self=shift();
	my $dir=shift();
	if (!defined($dir) || !-d "$$self{'Results'}/$dir"){
		return $$self{'Control'};
	}
	$$self{'Control'}=$dir;
	return $$self{'Control'};
}

sub setHostInfo {
	my $self=shift();
	my $output=shift();
	my $key=shift();
	my $value=shift();
	if (!defined($value)){
		return 0;
	}
	return $self->SetStatValue("$$self{'Results'}/${output}/hostInfo.txt","$key","$value");
}

# Host Vulnerability Status

sub SetIssue {
	my $self=shift();
	my $target=shift();
	my $message=shift();
	my $ref=shift();
	my $record;
	return 1 if (!$message);
	chomp $message; $message .= "\n";
	my $dir=$$self{'Results'} . "/$target/";
	if (open(FH,">$dir/.issues")){
		close FH;
		$$self{'Log'}->Issue("$message");
		return 0;
	}
	return 1;
}

sub SetVuln {
	my $self=shift();
	my $target=shift();
	my $message=shift();
	my $ref=shift();
	return 1 if (!$message);
	chomp $message; $message .= "\n";
	my $dir=$$self{'Results'} . "/$target/";
	if (open(FH,">$dir/.vuln")){
		close FH;
		$$self{'Log'}->Vuln("$message");
		return 0;
	}
	return 1;
}

sub SetComp {
	my $self=shift();
	my $target=shift();
	my $message=shift();
	my $ref=shift();
	return 1 if (!$message);
	chomp $message; $message .= "\n";
	my $dir=$$self{'Results'} . "/$target/";
	if (open(FH,">$dir/.comp")){
		close FH;
		$$self{'Log'}->Comp("$message");
		return 0;
	}
	return 1;
}

sub HasIssue {
	my $self=shift();
	my $target=shift();
	return 0 if (!$target);
	my $file=$$self{'Results'} . "/$target/.issues";
	return 1 if (-f "$file");
	return 0;
}
sub HasVuln {
	my $self=shift();
	my $target=shift();
	return 0 if (!$target);
	my $file=$$self{'Results'} . "/$target/.vuln";
	return 1 if (-f "$file");
	return 0;
}
sub HasComp {
	my $self=shift();
	my $target=shift();
	return 0 if (!$target);
	my $file=$$self{'Results'} . "/$target/.comp";
	return 1 if (-f "$file");
	return 0;
}


#*********************
# Status File Handling

sub ReadFile {
	# Reads $file into an array
	my $self=shift();
	my $file=shift();
	my $FH;
	if (-f $file && open($FH,$file)){
		flock($FH,LOCK_EX);
		my @FILE=<$FH>;
		flock($FH,LOCK_UN);
		close $FH;
		return @FILE;
	}
	return undef;
}

sub GetStatValue {
	# Matches first key in file and gets the value (space-separated)
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	my @FILE=$self->ReadFile($file);
	for my $f (@FILE){
		if ($f && index($f,"$key ")==0){
			my ($key,$val)=split (" ", $f, 2);
			return undef if (!defined($val));
			chomp $val;
			return $val;
		}
	}
	return undef;
}

sub GetStatKey {
	# Returns 1 if key exists in $file, 0 otherwise
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	my @FILE=$self->ReadFile($file);
	for my $f (@FILE){
#		if (defined($f) && $f =~ /^$key\s/){
		if (defined($f) && ((index($f,"$key ")==0) || (index($f,"$key\n")==0))){
			return 1;
		}
	}
	return 0;
}

sub GetStatKeys {
	# Returns an array of keys in $file
	my $self=shift();
	my $file=shift();
	my @FILE=$self->ReadFile($file);
	my @keys;
	for my $f (@FILE){
		if ($f && ($f =~ /^\S/) && ($f !~ /^#/)){
			my $key = substr($f,0,index($f," "));
			push @keys, $key;
		}
	}
	return @keys;
}

sub SetStatKey {
	# Sets $key in $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if (!$self->GetStatKey($file,$key)){
		if (open($FH,">>$file")){
			flock($FH,LOCK_EX);
			print $FH "$key \n";
			flock($FH,LOCK_UN);
			close $FH;
			return 1;
		}
	}
	return 0;
}

sub DelStatKey {
	# Removes $key from $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if ($self->GetStatKey($file,$key)){
		my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
		if (open($FH,$file)){
			flock($FH,LOCK_EX);
			$locked=1;
			@FILE=<$FH>;
		}

		for my $line (@FILE){
			if ($line && ((index($line,"$key ")==0) || (index($line,"$key\n")==0)) ) {
				$matched=1;
				next;
			}
			push @NEW, $line if ($line);
		}
		$#FILE=-1;

		if ($locked && $matched && open($FH,">$file")){
			print $FH @NEW;
			flock($FH,LOCK_UN);
			close $FH;
			$locked=0;
			$#NEW=-1;
			return 1;
		}
		if ($locked){
			flock($FH,LOCK_UN);
			close $FH;
		}
		$#NEW=-1;
	}
	return 0;
}

sub SetStatValue {
	# Sets $key=$value in $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;

	my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
	if (open($FH,$file)){
		flock($FH,LOCK_EX);
		$locked=1;
		@FILE=<$FH>;
	}

	for my $pair (@FILE){
		if ($pair && index($pair,"$key ")==0){
			$matched=1;
			push @NEW, "$key $value\n";
			next;
		}
		push @NEW, $pair if ($pair);
	}
	$#FILE=-1;

	if (!$matched){
		push @NEW, "$key $value\n";			
	}

	if (open($FH,">$file")){
		flock($FH,LOCK_EX) if (!$locked);
		print $FH @NEW;
		flock($FH,LOCK_UN);
		close $FH;
		$locked=0;
		$#NEW=-1;
		return 1;
	}
	if ($locked){
		flock($FH,LOCK_UN);
		close $FH;
	}
	$#NEW=-1;
	return 0;
}

sub AppendStatValue {
	# Appends "$key $value" to $file, even it if already exists
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;
	my $FH;
	if (open($FH,">>$file")){
		flock($FH,LOCK_EX);
		print $FH "$key $value\n";
		flock($FH,LOCK_UN);
		close $FH;
		return 1;
	}
	return 0;
}

sub DelStatKeyValue {
	# Removes "$key $value" from $file
	my $self=shift();
	my $file=shift();
	my $key=shift();
	my $value=shift();
	$key =~ s/\\/\\\\/g;
	$value =~ s/\\/\\\\/g;

	if ($self->GetStatValue($file,$key) eq $value){
		my (@FILE,@NEW,$FH); my ($matched,$locked)=(0,0);
		if (open($FH,$file)){
			flock($FH,LOCK_EX);
			$locked=1;
			@FILE=<$FH>;
		}

		for my $pair (@FILE){
			if ($pair && index($pair,"$key $value")==0){
				$matched=1;
				next;
			}
			push @NEW, $pair if ($pair);
		}
		$#FILE=-1;

		if ($locked && $matched && open($FH,">$file")){
			print $FH @NEW;
			flock($FH,LOCK_UN);
			close $FH;
			$locked=0;
			$#NEW=-1;
			return 1;
		}
		if ($locked){
			flock($FH,LOCK_UN);
			close $FH;
		}
		$#NEW=-1;

	}
	return 0;

}

# For lists of keys without values, such as LiveHosts list.
# SetListItem will not allow duplicate entries, AND it doesn't
# put a space on the end of each line.

sub SetListItem {
	my $self=shift();
	my $file=shift();
	my $key=shift();
	$key =~ s/\\/\\\\/g;
	if (!$self->GetStatKey($file,$key)){
		my $FH;
		if (open($FH,">>$file")){
			flock($FH,LOCK_EX);
			print $FH "$key\n";
			flock($FH,LOCK_UN);
			close $FH;
			return 1;
		}
	}
	return 0;
}















1;

