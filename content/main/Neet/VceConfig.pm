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

package Neet::VceConfig;

sub new {
	my $pkg=shift();
	my $file=shift();
	my %data;
	my %section;
	my $self=\%data;
	my $id=0;
	if (open(VE,$file)){

		until (eof VE){
			my $line=readline(*VE);
			next if ($line !~ /^[\w\[]/);
			if ($line =~ /^\[CHECK\]/){
				addConf();
				next;
			}
			chomp $line;
			my ($key,$value)=split (" ", $line ,2);
			$section{$key}=$value;
		}
		close VE;
		addConf();
	} else {
		return undef;
	}

	sub addConf {
		no warnings;
		if ($section{'name'}){
			for my $key (keys(%section)){
				$data{$id}{$key}=$section{$key};
			}
			$id++;
			$data{'total'}=$id;
		}
		%section=();
	}
	bless $self, $pkg;
	return $self;
}

sub totalChecks {
	my $self=shift();
	return $$self{'total'};
}

sub AllChecks {
	my $self=shift();
	my $type=shift();
	my @keys;
	for (my $id=0; $id < $$self{'total'}; $id++){
		if ($type){
			my $t=$self->Type($id);
			next if ("$t" ne "$type");
		}
		push @keys, $id;
	}
	return @keys;
}

sub Checks {
	my $self=shift();
	my $type=shift();
	my @keys;
	for (my $id=0; $id < $$self{'total'}; $id++){
		next if (! $self->Enabled($id));
		if ($type){
			my $t=$self->Type($id);
			next if ("$t" ne "$type");
		}
		push @keys, $id;
	}
	return @keys;
}

sub Type {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'type'};
}
sub Name {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'name'};
}
sub Label {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'label'};
}
sub Desc {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'desc'};
}
sub Xterm {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'xterm'};
}
sub Udpport {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'udpport'};
}
sub Tcpport {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'tcpport'};
}
sub Enabled {
	my $self=shift();
	my $id=shift();
	if ($$self{$id}{'enabled'} == "1"){
		return 1;
	}
	return 0;
}

sub Msref {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'msref'};
}
sub Cve {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'cve'};
}
sub Bid {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'bid'};
}
sub Check {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'check'};
}
sub Vuln {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'vuln'};
}
sub Exarch {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'exarch'};
}
sub Extype {
	my $self=shift();
	my $id=shift();
	my $a= $$self{$id}{'extype'};
	if ($a){
		return $a;
	}
	return 0;

}
sub Exmancmd {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'exmancmd'};
}
sub Exautocmd {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'exautocmd'};
}

sub Exautosafe {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'exautosafe'};
}
sub Credentialtype {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'credentialtype'};
}
sub NoTest {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'notest'};
}

sub Exmanusafe {
	my $self=shift();
	my $id=shift();
	return $$self{$id}{'exmanusafe'};
}

sub GetVal {
	my $self=shift();
	my $id=shift();
	my $key=shift();
	return $$self{$id}{$key};
}

1;
