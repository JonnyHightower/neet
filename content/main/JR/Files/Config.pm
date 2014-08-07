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

package Config;
use Fcntl ':flock';

# Config file parsing for Neet
# Jonathan Roach
# April 2006
# Version

sub new {
	my $self=shift;
	my $file=shift();
	my @contents;
	my %Config;
	my $F;
	if ($file && -f "$file" && open($F,"$file")){
		until (eof $F){
			my $line=readline (*$F);
			next if (($line !~ /\S/) || ($line =~ /^[\s]{0,}\#/));
			chomp $line;
			push @contents,$line
		}
		close $F;
	} else {
		return 0;
	}
	$Config{'File'}=$file;
	$Config{'Contents'}=\@contents;

	my $object=\%Config;
	bless $object, $self;
	return $object;
}

sub Split {
	my $self=shift();
	my $line=shift();
	return 0 if (!$line || $line !~ /=/);
	my $sp=index($line,"=");
	my $key=substr($line,0,$sp);
	my $value=substr($line,$sp+1,length($line)-($sp+1));
	return ($key,$value);
}

sub ListKeys {
	my $self=shift();
	my @keys;
	for my $line (@{$$self{'Contents'}}){
		my ($k,$v)=$self->Split($line);
		push @keys, $k;
	}
	return @keys;
}

sub GetVal {
	my $self=shift();
	my $key=shift();
	for my $line (@{$$self{'Contents'}}){
		my ($k,$v)=$self->Split($line);
		if ("$k" eq "$key"){
			return $v;
		}
	}	
	return undef;
}

sub GetClassValues {
	my $self=shift();
	my $class=shift();
	my @values;
	for my $line (@{$$self{'Contents'}}){
		my ($k,$v)=$self->Split($line);
		if ($k =~ /^$class/){
			push @values, $v;
		}
	}	
	return @values;
}

sub GetClassKeys {
	my $self=shift();
	my $class=shift();
	my @keys;
	for my $line (@{$$self{'Contents'}}){
		my ($k,$v)=$self->Split($line);
		if ($k =~ /^$class/){
			$k =~ s/$class//;
			push @keys, $k;
		}
	}	
	return @keys;
}

sub UpdateValueInFile {
	my $self=shift();
	my $class=shift();
	my $value=shift();
	my (@oldfile,@newfile,$changed);
	if (defined($class) && defined($value) && open(FH,$$self{'File'})){
		flock(FH,LOCK_EX);
		@oldfile=<FH>;
		flock(FH,LOCK_UN);
		close FH;
		for my $line (@oldfile){
			if ($line =~ /^${class}=/){
				$line = "${class}=$value\n";
				$changed=1;
			}
			push @newfile, $line;
		}
		$#oldfile=-1;

		if ($changed && open(FH,">$$self{'File'}")){
			flock(FH,LOCK_EX);
			print FH @newfile;
			flock(FH,LOCK_UN);
			close FH;
			$#newfile=-1;
			return 1;
		}
	}
	return 0;
}

1;
