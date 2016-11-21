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

package Neet::threads;
use Storable;
use POSIX ":sys_wait_h";

$SIG{'CHLD'}='Neet::threads::reaper';

my %threads;

sub create {
	Neet::threads->_check();
	my $obj=shift(@_);
	my $callback=shift(@_);
	my @params=@_;
	my $pid=fork();

	if ($pid){
		$Neet::threads::threads{'currentid'}++;
		$Neet::threads::threads{'pids'}{$Neet::threads::threads{'currentid'}}=$pid;
		$Neet::threads::threads{'tids'}{$pid}=$Neet::threads::threads{'currentid'};

		my %thread; $thread{'id'}=$Neet::threads::threads{'currentid'};
		$thread{'pid'}=$pid; $thread{'function'}=$callback; @{$thread{'parameters'}}=@params;
		$thread{'type'}='thread'; $thread{'storage'}="$Neet::threads::threads{'storage'}/$pid";
		my $threadObject=\%thread;
		bless $threadObject, $obj;
		push @{$Neet::threads::threads{'threads'}}, $threadObject;
		return $threadObject;

	} else {

		$Neet::threads::threads{'currentid'}++;
		$Neet::threads::threads{'pids'}{$Neet::threads::threads{'currentid'}}=$pid;
		my $storage="$Neet::threads::threads{'storage'}/$$";

		# Allow the thread to call "self" and access its own object
		my %thread; $thread{'id'}=$Neet::threads::threads{'currentid'};
		$thread{'pid'}=$$; $thread{'function'}=$callback; @{$thread{'parameters'}}=@params;
		$thread{'type'}='thread'; my $threadObject=\%thread; $thread{'storage'}=$storage;
		bless $threadObject, $obj;
		push @{$Neet::threads::threads{'threads'}}, $threadObject;

		my @results=&{"main::$callback"};
		if (@results){
			mkdir $storage;
			close A if (open (A,">$storage/out"));
			chmod oct('700'), "$storage/out";
			store \@results, "$storage/out";
		}
		exit 0;
	}
}

sub reaper {
	my $child=1;
	do {
		$child= waitpid(-1, WNOHANG);
	} while $child>0;
}

sub join {
	my $self=shift();
	return undef if (!defined($self));
	my @return;
	if (exists($$self{'type'})){
		if (!$self->is_running){
			my $tid=$self->tid;
			my $pid=$self->pid;
			$Neet::threads::threads{'pids'}{$tid}=undef;
			${$Neet::threads::threads{'threads'}}[$tid]=undef;
			# Read back return values;
			my $storage="$Neet::threads::threads{'storage'}/$pid";
			if (-f "$storage/out"){
				my $ref=retrieve "$storage/out";
				unlink "$storage/out";
				rmdir "$storage";
				@return = @{$ref};
			}
		}
	}
	return @return;
}

sub pid {
	my $self=shift();
	if (exists($$self{'pid'})){
		return $$self{'pid'};
	}
	return $$;
}

sub tid {
	my $self=shift();
	if (exists($$self{'id'})){
		return $$self{'id'};
	}
	return 0 if ($$ eq $Neet::threads::threads{'pids'}{0});
	return $Neet::threads::threads{'currentid'};
}

sub self {
	my $tid=$Neet::threads::threads{'currentid'};
	return undef if ($$ eq $Neet::threads::threads{'pids'}{0});
	my $self=@{$Neet::threads::threads{'threads'}}[$tid];
	return $self;
}

sub callback {
	my $self=shift();
	return undef if (!defined($self));
	if (exists($$self{'callback'})){
		return $$self{'callback'};
	}
	return undef;
}

sub parameters {
	my $self=shift();
	return undef if (!defined($self));
	if (exists($$self{'id'})){
		return @{$$self{'parameters'}};
	}
	return undef;
}

sub is_running {
	my $self=shift();
	return 0 if (!defined($self));
	if (exists($$self{'pid'})){
		my $dir="/proc/$$self{'pid'}";
		if (-d $dir){
			return 1;
		}
	}
	return 0;
}

sub kill {
	Neet::threads->_check();
	my $self=shift();
	if (exists($$self{'id'})){
		my $signal=shift();
		return kill ($signal, $$self{'pid'});
	}
	return undef;
}

sub object {
	my $tid=shift();
	# Prevent threads calling other threads as this information may not be available
	return undef if ($$ != $Neet::threads::threads{'pids'}{0});
	return ${$Neet::threads::threads{'threads'}}[$tid];
}

sub is_joinable {
	my $self=shift();
	return 1 if (!$self->is_running);
	return 0;
}

sub running {
	Neet::threads->_check();
	my @running;
	for my $i (1..$Neet::threads::threads{'currentid'}){
		if (defined(${$Neet::threads::threads{'threads'}}[$i]) && ${$Neet::threads::threads{'threads'}}[$i]->is_running){
			push @running, ${$Neet::threads::threads{'threads'}}[$i];
		}
	}
	return @running;
}

sub joinable {
	my @joinable;
	for my $i (1..$Neet::threads::threads{'currentid'}){
		if (defined(${$Neet::threads::threads{'threads'}}[$i]) && !${$Neet::threads::threads{'threads'}}[$i]->is_running){
			push @joinable, ${$Neet::threads::threads{'threads'}}[$i];
		}
	}
	return @joinable;
}

sub all {
	my @all;
	for my $i (1..$Neet::threads::threads{'currentid'}){
		if (defined(${$Neet::threads::threads{'threads'}}[$i])){
			push @all, ${$Neet::threads::threads{'threads'}}[$i];
		}
	}
	return @all;
}

sub equal {
	my $thr1=shift();
	my $thr2=shift();
	if (exists($$thr1{'pid'}) && exists($$thr2{'pid'})){
		if ($$thr1{'pid'} == $$thr2{'pid'}){
			return 1;
		}
	}
	return 0;
}

sub list {
	Neet::threads->_check();
	my $cmd=shift();
	if (!defined($cmd)){
		return all();
	} elsif ($cmd eq "running"){
		return running();
	} elsif ($cmd eq "joinable"){
		return joinable();
	}
	return undef;
}


sub _check {
	my $obj=shift();
	if (!exists($Neet::threads::threads{'currentid'})){
		$Neet::threads::threads{'pids'}{0}=$$;
		$Neet::threads::threads{'currentid'}=0;

		my %thread; $thread{'id'}=0;
		$thread{'pid'}=$$;
		my $threadObject=\%thread;
		bless $threadObject, $obj;
		push @{$Neet::threads::threads{'threads'}}, $threadObject;

		my $user=$ENV{'USER'};
		if (!defined($user)){
			$user=`/usr/bin/id -un`;
		}
		$Neet::threads::threads{'storage'}="/tmp/Neet::threads-${user}/";
		if (! -d "$Neet::threads::threads{'storage'}"){
			mkdir "$Neet::threads::threads{'storage'}";
			chmod oct('700'), "$Neet::threads::threads{'storage'}";
			
		}
		$Neet::threads::threads{'storage'}="/tmp/Neet::threads-${user}/$$";
		if (! -d "$Neet::threads::threads{'storage'}"){
			mkdir "$Neet::threads::threads{'storage'}";
			chmod oct('700'), "$Neet::threads::threads{'storage'}";
		}
	}
}

sub exit {
	my $obj=shift();
	my $code=shift();
	$code=0 if (!$code);
	exit $code;
}

1;

