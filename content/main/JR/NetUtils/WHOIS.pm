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

package JR::NetUtils::WHOIS;

sub new {
	use IO::Socket::INET;
	my $pkg=shift();
	my %object;
	@{$object{'sources'}}=("whois.ripe.net","whois.arin.net","whois.apnic.net","whois.lacnic.net","whois.afrinic.net");
	my $self=\%object;
	bless $self, $pkg;
	return $self;
}

sub lookup {
	my $self=shift();
	my $record=shift();
	for my $source (@{$$self{'sources'}}){
		my $res=$self->query_server($source,$record);
		return 1 if ($res);
	}
	return 0;
}


sub data {
	my $self=shift();
	return @{$$self{'data'}};
}
sub source {
	my $self=shift();
	return $$self{'source'};
}

sub query_server {
	my $self=shift();
	my $source=shift();
	my $record=shift();
	my $success=0;
	my @data;
	my $sock=IO::Socket::INET->new( 'Proto' => 'tcp', 'PeerAddr' => "$source",
																											'PeerPort' => '43');
	if ($sock){
		print $sock "$record\n";
		@data=<$sock>;
		close $sock;
		for my $line (@data){
			if ($line =~ /^ReferralServer:\s/){
				my ($j,$s) = split (" ", $line, 2);
				$s =~ s/whois:\/\/([\S]+)\W/$1/;
				$$self{'referral'}=$s;
				$success=0;
				last;
			}
			if ($line =~ /^person:\s/ || $line =~ /^origin:\s/ || $line =~ /^NameServer:\s/ || $line =~ /^OrgName:\s/){
				$success=1;
			}

		}
		if ($success){
			@{$$self{'data'}}=@data;
			$$self{'source'}=$source;
		}
	}
	return $success;
}

1;

