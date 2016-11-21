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

# ThreadPool.pm

# Basic thread pool emulation at process level
# J Roach 2006.

package JR::Process::ThreadPool;
use Fcntl ':flock';

sub new {
	my $pkg=shift();
	my $num=shift();
	my $sub=shift();
	return undef if (!$sub);
	my @params=@_;
	my $dbg=0;

	# Create a 'cookie' to identify this pool even if another
	# pool is started by the same process
	my @chars=('A'..'Z','a'..'z',0..9);
	my $cookie=$$;
	for (my $a=0; $a<14; $a++){
		$cookie .= $chars[int(rand(62))];
	}
	$#chars=-1;

	my @threads;
	my %pool;
	$pool{'debug'}=$dbg;
	$pool{'threads'}=\@threads;
	$pool{'number'}=0;
	$pool{'lastid'}=0;
	$pool{'params'}=\@params;
	$pool{'min'}=$num;
	$pool{'max'}=$num;
	$pool{'sub'}=$sub;
	$pool{'cookie'}=$cookie;
	$pool{'dir'}=$ENV{'HOME'} . "/.ThreadPool/$cookie/";
	if (!-d $pool{'dir'}){
		system("mkdir -p $pool{'dir'}");
		chmod 0700, $pool{'dir'};
	}
	
	# Create the object so we can use it straight away
	my $ThreadPool=\%pool;
	bless $ThreadPool, $pkg;

	# This is where we create the pool - before the main program stream
	# gets too populated - particularly before the workload is generated.
	for (my $th=0; $th<$pool{'min'}; $th++){
		$ThreadPool->_CreateThread;
	}

	$pool{'openbatch'}=0;

	# Return the object
	return $ThreadPool;
}

sub Create {
	my $pkg=shift();
	my $object=$pkg->new(@_);
	return $object;
}

sub Destroy {
	# Kills all waiting threads
	my $self=shift();
	for my $PID (@{$$self{'threads'}}){
		print "Stopping $PID\n" if ($$self{'debug'});
		system ("kill $PID");
	}
	system ("rm -r $$self{'dir'} 2>/dev/null");
	undef $self;
}

# *********************************
# Controlling the number of threads

# We want one more
sub AddThread {
	my $self=shift();
	if (($$self{'number'} < $$self{'max'}) && $self->_CreateThread){
		return 1;
	}
	return 0;
}

# We want one less (will wait until one becomes idle and stop it)
sub DelThread {
	my $self=shift();
	if ($$self{'number'} > $$self{'min'}){
		# Find a spare thread
		my $IdleThread=$self->__GetSpareThread;
		if ($self->StopThread($IdleThread)){
			return 1;
		}
	}
	return 0;
}

# How many are currently running
sub CurrentThreads {
	my $self=shift();
	return $$self{'number'};
}

# Get / Set the maximum number
sub MaxThreads {
	my $self=shift();
	my $max=shift();
	if ($max){
		if ($max > $$self{'max'}){
			$$self{'max'}=$max;
			return $max;
		}
		return 0;
	}
	return $$self{'max'};
}

# Stop a specific thread ID
sub StopThread {
	my $self=shift();
	my $threadID=shift();
	my $pipe=$self->__ThreadPipe($threadID);
	if (!-f $pipe){
		$self->__AssignTaskToThread($threadID,"exitThread");
		$$self{'number'}--;
		$self->__DeleteThread($threadID);
		return 1;
	}
	return 0;
}

# ***********************
# Assigning tasks to threads

sub OpenBatch {
	my $self=shift();
	$$self{'openbatch'}=1;
	$$self{'finishedalloc'}=0;
	return 1;
}

sub AllocateItem {
	my $self=shift();
	my $workload=shift();
	return undef if (!$workload);
	return undef if (!$$self{'openbatch'});
	print "Allocating workload as an item\n" if ($$self{'debug'});
	my $thread=$self->__GetSpareThread;
	$self->__AssignTaskToThread($thread,$workload);
	print "Finished allocating workload item\n" if ($$self{'debug'});
	return 1;
}

sub CloseBatch {
	my $self=shift();
	$$self{'openbatch'}=0;
	$$self{'finishedalloc'}=1;
	return 1;
}

sub AllocateArray {
	my $self=shift();
	my $workload=shift();
	return undef if (!$workload);
	$$self{'finishedalloc'}=0;
	print "Allocating workload from array\n" if ($$self{'debug'});
	for my $cmd (@{$workload}){
		my $thread=$self->__GetSpareThread;
		$self->__AssignTaskToThread($thread,$cmd);
	}
	print "Finished allocating workload\n" if ($$self{'debug'});
	$$self{'finishedalloc'}=1;
	return 1;
}

# ***********************
# Determine when the entire threadpool is idle
sub ThreadsComplete {
	my $self=shift();
	return 0 if (!$$self{'finishedalloc'});
	my @spare=$self->__ListSpareThreads;
	if ($#spare == ($$self{'number'} - 1)){
		return 1;
	}
	print "Threads NOT complete\n" if ($$self{'debug'}>1);
	return 0;
}

sub WaitForThreadsComplete {
	my $self=shift();
	until ($self->ThreadsComplete){
		sleep 1;
	}
	return 0;
}

# ***********************
# *** Private Methods ***

# Creates and implements new thread
sub _CreateThread {
	my $self=shift();
	my $threadID=$$self{'lastid'}+1;
	my $newThread=fork();
	if ($newThread){
		$$self{'number'}++;
		$$self{'lastid'}++;
		print "Created thread: $threadID (PID $newThread)\n" if ($$self{'debug'});
		$$self{'thread'}{'ref'}{$threadID}{'pid'}=$newThread;
		$$self{'thread'}{'pid'}{$newThread}{'ref'}=$threadID;
		push @{$$self{'threads'}}, $newThread;
		return $newThread;
	} else {
		# This is the new thread
		my $sub=$$self{'sub'};
		my $task;
		print "This is a new thread - ID $threadID (PID $$)\n" if ($$self{'debug'});
		until ($task && ("$task" eq "exitThread")){
			$task=$self->__ThreadGetTask;
			if ($task){
				last if ("$task" eq "exitThread");
				print "This thread - ID $threadID (PID $$) running task $task\n" if ($$self{'debug'}>1);
				my $res=&$sub($task,$threadID,@{$$self{'params'}});
				$self->__ThreadTaskComplete;
			} else {
				sleep 1;
			}
		}
		my $pipe=$$self{'dir'} . $$;
		print "Thread PID $$ - exitThread instruction - unlinking $pipe\n" if ($$self{'debug'}>1);
		unlink $pipe;
		exit 0;
	}
	return 0;
}

# Thread-related lookups
sub __ThreadMyRef {
	my $self=shift();
	my $pid=shift();
	$pid=$$ if (!$pid);
	return $$self{'thread'}{'pid'}{$pid}{'ref'};
}

sub __ThreadMyPID {
	my $self=shift();
	my $ref=shift();
	return $$self{'thread'}{'ref'}{$ref}{'pid'};
}

sub __ThreadList {
	my $self=shift();
	return @{$$self{'threads'}};
}
	
sub __DeleteThread {
	my $self=shift();
	my $threadID=$self->__ThreadMyPID(shift());
	my @tmp;
	while (my $tid=shift(@{$$self{'threads'}})){
		if ($tid != $threadID){
			push @tmp, $tid;
		}
	}
	push @{$$self{'threads'}}, @tmp;
	$#tmp=-1;
	return 0;
}

sub __ListSpareThreads {
	my $self=shift();
	my @spare;
	for my $pid ($self->__ThreadList){
		my $thread=$self->__ThreadMyRef($pid);
		my $pipe=$self->__ThreadPipe($thread);
		if (!-f $pipe){
			push @spare, $thread;
		}
	}
	return @spare;
}

sub __GetSpareThread {
	my $self=shift();
	my $spare=0; my $thread;
	until ($spare){
		for my $_thread ($self->__ListSpareThreads){
			$spare++; $thread=$_thread;
			last;
		}
		sleep 1 if (!$spare);
	}
	print "Got spare thread ref: $thread\n" if ($$self{'debug'}>1);
	return $thread;
}

sub __ThreadPipe {
	my $self=shift();
	my $thread=shift();
	my $pipe=$$self{'dir'} . $$self{'thread'}{'ref'}{$thread}{'pid'};
	return $pipe;
}

sub __AssignTaskToThread {
	my $self=shift();
	my $thread=shift();
	my $cmd=shift();
	return 0 if (!$cmd);
	my $pipe=$self->__ThreadPipe($thread);
	print "Assigning $cmd to $thread via pipe $pipe\n" if ($$self{'debug'}>1);
	if (open(TSK,">$pipe")){
		flock (TSK,LOCK_EX);
		print TSK $cmd;
		flock (TSK,LOCK_UN);
		close TSK;
		chmod 0700, "$pipe";
	}
	return $cmd;
}

#----------------------------

sub __ThreadGetTask {
	my $self=shift();
	my $task; my $pipe=$$self{'dir'} . $$;
	print "Thread PID $$ - checking $pipe for new tasks\n" if ($$self{'debug'}>1);
	if (open(TSK,$pipe)){
		flock (TSK,LOCK_EX);
		$task=<TSK>;
		flock (TSK,LOCK_UN);
		chomp $task;
		close TSK;
	}
	return $task;
}

sub __ThreadTaskComplete {
	my $self=shift();
	my $pipe=$$self{'dir'} . $$;
	print "Thread PID $$ - task complete - unlinking $pipe\n" if ($$self{'debug'}>1);
	unlink $pipe;
}

1;


__END__

=head1 NAME

ThreadPool - A PERL module for emulating a parallel thread pool at process level.

=head1 SYNOPSIS

	use ThreadPool;

	# Create the ThreadPool object and spawn all the threads. These will idle until
	# some work is allocated to the pool.

	my $ThreadPool=ThreadPool->new($numberThreads,\&ProcessingSubroutine,$debugLevel);

	# Batch processing. OpenBatch() will indicate that you wish to use batch processing.

	$ThreadPool->OpenBatch;

	# AllocateItem will directly allocate $item to the thread pool. Call this as many 
	# times as you need to.

	$ThreadPool->AllocateItem($item);

	# When you have finished processing items, close the batch

	$ThreadPool->CloseBatch;

	# Array processing. AllocateArray will allocate each item in the referenced array
	# to a thread for processing. 

	$ThreadPool->AllocateArray(\@Array);

	# Wait for all of the threads to become idle with no more work to allocate

	until ($ThreadPool->ThreadsComplete){
		sleep 2;
	}

	# When you have finished with the thread pool, you need to clean up. The Destroy()
	# method will terminate any running threads.
	$ThreadPool->Destroy;

=head1 DESCRIPTION

This module provides an easy way to run several simultaneous identical processes, each
one processing different information.

The module does NOT require your PERL interpreter to be built with threading support,
as the thread pool consists of individual processes, NOT threads - interpreter-based or
otherwise.

=head1 WHY

Forking new processes is computationally expensive. When I wrote this module, I was
working on a program that would need to connect to thousands of computers in as short
a time as possible. As the networking code involves a lot of blocking, it made sense
to make it multi threaded - even on a single CPU - so that when one process blocks,
others can carry on. I originally made the program multi threaded in the sense that
it would fork a new process to connect to each machine.

I soon found the cost of doing this as my program was using most of the CPU and not
much of the network. I investigated the native multi-threading that ships with PERL 
5.8.0 and later, but a lot of the standard modules aren't thread-safe, and there were
some process-wide functions, such as chdir() that when called in one thread, would affect
every thread. 

ThreadPool solves the problems by forking a fixed number of separate processes, then
assigning each one an item to process. As a process becomes free, the next item is
assigned to it for processing. 

The net effect is that all the expensive forking is done once, at the start of the
program, and then it doesn't need to be done again. 

=head1 METHODS

=item new()

	The new() method is used to create the thread pool. It takes two mandatory parameters:

	int numberThreads - the number of threads to spawn and keep in the pool. This can be
	increased (but not decreased) later with MaxThreads() and AddThread().

	Subroutine - a Reference to the subroutine that will be called by each thread and which
		will process the information

	Optionally, a third integer parameter can be passed to indicate a debug level, which 
	simply produces verbose output. If omitted, the debug level is 0.

	When correctly called, the new() method causes a pool of $numberThreads threads
	to be spawned, and then returns an instance of a ThreadPool object. The threads
	sit idling until they are either allocated tasks or terminated.

=item Create()

	This is a wrapper around the new() method, and has identical usage and effects.

=item ThreadsComplete()

	This returns 1 if all tasks have been assigned and completed and there is no open
	batch. Otherwise, it returns 0.

	This does NOT mean that the threads have terminated. It means that they are idle, and
	they can be used again without instantiating a new object.

=item WaitForThreadsComplete()

	This function returns when ThreadsComplete returns 1, and not before.

=item Destroy()

	This method is required to terminate the running threads - otherwise they will run 
	indefinitely. It also cleans up the disk area that the threads use to communicate.
	Finally, it destroys the ThreadPool object.

	As ThreadPool will leave a mess if you don't call this method, I suggest that you
	use a signal handler to trap at least SIGINT, and call Destroy():

	$SIG{'INT'}=sub {
		$ThreadPool->Destroy;
		exit 255;
	}

=item MaxThreads()

	Called without an argument, returns the maximum number of threads. Called with an argument
	of "n", sets the maximum number of threads to "n".

=item CurrentThreads()

	Returns the number of threads currently running, idle or not.

=item AddThread()

	Adds a new thread to the pool (as long as CurrentThreads() is less than
	MaxThreads())

=item StopThread()

	Issues a stop command to the specified thread ID. It will stop and exit once it has finished
	the current task.

=item DelThread()

	Waits for a thread to become idle, and then calls StopThread() on it.

=item AllocateArray()

	AllocateArray takes a reference to an array as a parameter, and iterates over the
	array, allocating each item to the next idle process until the entire array has
	been allocated. AllocateArray returns when all items have been allocated, NOT
	when all threads are complete.

	AllocateArray can be called multiple times in succession on the same thread pool.
	This enables iteration over several arrays by the same thread pool.

=item AllocateItem()

	AllocateItem takes a scalar as a parameter, and allocates it to the next idle
	process. This method is designed to be used when your program generates data
	for processing at various stages of the code, and you don't have all the data
	in a handy array.

	AllocateItem is meant to be called multiple times in succession on the same
	thread pool. However, you must first have enabled Batch mode by calling the
	OpenBatch() method.

	When you have finished adding items with AllocateItem, you MUST close the
	batch by calling CloseBatch(), otherwise WaitForThreadsComplete() will never
	return (because ThreadsComplete() will always return 0).

=item OpenBatch()

	Indicates that a batch of items is about to be allocated, and enables that allocation
	via AllocateItem()

=item CloseBatch()

	Indicates that no more items are to be allocated, and disables further allocation
	via AllocateItem()

=head1 AUTHOR

Jonathan Roach 2006 - www.packetsnarf.net
