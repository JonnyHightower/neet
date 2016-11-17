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

package Neet::GlobalServiceMonitor;
# Ensure we can find our Perl modules
BEGIN {
	unshift @INC, "/opt/neet/core";
}

use File::Find;
use Neet::threads;

sub new {
	my $pkg=shift();
	my %engine;
	$engine{'MainScan'}=shift();
	my (@foundModules,@loadedModules,@loadedObjects,@failedModules,@watchFiles,@Queue,@costs,@threads,@DispatchedModules,@DispatchedQueue,@singleScanned);
	$engine{'Budget'}=shift();
	$engine{'ModuleDir'}=$engine{'MainScan'}->Config->GetVal('ModulesDirectory');
	$engine{'LimitGsms'}=0;
	$engine{'Threads'}{'IDs'}=\@threads;
	$engine{'Modules'}{'Found'}=\@foundModules;
	$engine{'Modules'}{'Failed'}=\@failedModules;
	$engine{'Modules'}{'Loaded'}{'Names'}=\@loadedModules;
	$engine{'Modules'}{'Loaded'}{'Objects'}=\@loadedObjects;
	$engine{'Modules'}{'Loaded'}{'Costs'}=\@costs;
	$engine{'Used'}=0;
	$engine{'startedAnotherThread'}=0;
	$engine{'LoadTarget'}=300;
	$engine{'InteractionFileModifiedTime'}=0;
	$engine{'WatchFiles'}{'List'}=\@watchFiles;
	$engine{'Queue'}=\@Queue;
	$engine{'Dispatched'}=\@DispatchedQueue;
	$engine{'singleScanned'}=\@singleScanned;
	my $self=\%engine;
	bless $self, $pkg;	

	$self->LoadModules;
	return $self;
}

sub ProcessQueue {
	my $self=shift();
	my $available=$self->FreeBudget;
	if ($available){
		$$self{'MainScan'}->Log->Debug("ProcessQueue: Available budget $available") if ($$self{'MainScan'}->Debug>2);
		for my $item (@{$$self{'Queue'}}){
			my ($module,$file,$target)=split (":", $item, 3);
			my $moduleObject=$self->Module($module);
			my $cost=$moduleObject->Cost;
			my $okToProcess=1;

			# Is the module disabled?
			if ($self->ModuleDisabled($module)){
				$okToProcess=0;
				$$self{'MainScan'}->Log->Debug("ProcessQueue: Can't start $module on $target - module disabled by user") if ($$self{'MainScan'}->Debug);
				next;
			}

			# Check that the target host is up
			my $host=$target; $host = substr($host,0,index($host,":")) if ($host =~ /:/);
			if (! -d $host){
				$okToProcess=0;
				$self->RemoveFromQueue($item);
				next;
			}

			# Check if there are instances of conflicting modules running
			for my $conflictingModule ($moduleObject->ConflictsWith){
				if ($#{$$self{'Modules'}{'Instances'}{$conflictingModule}} >= 0){
					$$self{'MainScan'}->Log->Debug("ProcessQueue: Can't start $module on $target - conflicts with $conflictingModule") if ($$self{'MainScan'}->Debug>1);
					$okToProcess=0;
					next;
				}
			}
			if (!defined($$self{'Modules'}{'Instances'}{$module})){
				$$self{'Modules'}{'Instances'}{$module}=0;
			}
			# Check if there's enough budget left and that the number of modules running is less than the maximum allowed.
			my $maxInstances=$moduleObject->MaxInstances;
			if (($cost > $available) || ($maxInstances > 0 && ($$self{'Modules'}{'Instances'}{$module} >= $maxInstances))){
					$$self{'MainScan'}->Log->Debug("ProcessQueue: Can't start $module on $target - not enough budget or too many instances") if ($$self{'MainScan'}->Debug>1);
					$okToProcess=0;
					next;
			}
			if ($okToProcess){
				$$self{'Used'} += $cost;
				$$self{'Modules'}{'Instances'}{$module}++;
				$self->RemoveFromQueue($item);
				$available=$self->FreeBudget;
				$$self{'MainScan'}->Log->Debug("ProcessQueue: Assigning $item") if ($$self{'MainScan'}->Debug>1);
				$self->Assign($module,$file,$target);
			}
		}
	}

	# Now collect any threads which have finished

	for my $id (@{$$self{'Threads'}{'IDs'}}){
		if ($$self{'Threads'}{$id}{'thread'}->is_joinable){
			my @results=$$self{'Threads'}{$id}{'thread'}->join;
			$$self{'MainScan'}->Log->Debug("Joined thread $id: module $$self{'Threads'}{$id}{'module'} on $$self{'Threads'}{$id}{'target'} releasing budget $$self{'Threads'}{$id}{'cost'}\n","LOGONLY") if ($$self{'MainScan'}->Debug);
			
			$$self{'Modules'}{'Instances'}{$$self{'Threads'}{$id}{'module'}}--;
			$$self{'Used'} -= $$self{'Threads'}{$id}{'cost'};

			# Remove the ID from the array of threads
			my @newThreads;
			for my $oid (@{$$self{'Threads'}{'IDs'}}){
				push @newThreads, $oid if ($oid != $id);
			}
			@{$$self{'Threads'}{'IDs'}}=@newThreads;
			# And finally delete the unused data
			$#newThreads=-1;
			$$self{'Threads'}{$id}=undef;
		}
	}
}

sub QueueSize {
	my $self=shift();
	return ($#{$$self{'Queue'}} +1);
}

sub setUIPID {
	my $self=shift();
	my $pid=shift();
	$$self{'UIPID'}=$pid;
}

sub Assign {
	my $self=shift();
	my $module=shift();
	my $file=shift();
	my $target=shift();
	my $moduleObject=$self->Module($module);
	my $cost=$moduleObject->Cost;
	$moduleObject->TargetSpec($target);
	my $thread=Neet::threads->create("${module}::activate", $moduleObject, $target, $file);
	$$self{'startedAnotherThread'}=1;
	my $id=$thread->tid;
	$$self{'MainScan'}->Log->Debug("Spawned thread $id: module $module (cost $cost) testing $target.\n","LOGONLY") if ($$self{'MainScan'}->Debug);
	push @{$$self{'Threads'}{'IDs'}}, $id;
	$$self{'Threads'}{$id}{'thread'}=$thread;
	$$self{'Threads'}{$id}{'module'}=$module;
	$$self{'Threads'}{$id}{'target'}=$target;
	$$self{'Threads'}{$id}{'file'}=$file;
	$$self{'Threads'}{$id}{'cost'}=$cost;	
	return $thread;
}

sub singleScanned {
	my $self=shift();
	my $item=shift();
	for my $ss (@{$$self{'singleScanned'}}){
		if ($ss eq $item){
			return 1;
		}
	}
	return 0;
}

sub QueueTargets {
	my $self=shift(); my $junk;
	for my $file (@{$$self{'WatchFiles'}{'List'}}){
		next if (!-f $file);
		if ($self->FileUpdated("$file")){
			$$self{'MainScan'}->Log->Debug("QueueTargets: watchfile $file UPDATED") if ($$self{'MainScan'}->Debug>1);
			# Update the last modified time for the file
			$$self{'WatchFiles'}{'Data'}{'Modified'}{$file} = $self->FileModifiedTime($file);
			# Process the items in the file
			my $index=index($file,"/services/")+10;
			my $basename = substr($file,$index,(length($file)-$index));
			for my $target ($$self{'MainScan'}->GetStatKeys($file)){
				for my $module (@{$$self{'WatchFiles'}{'Watching'}{$file}}){
					my $item="$module:$basename:$target";
					if ($self->Module($module)->SingleScan){
						($target,$junk)=split (":", $target);
						$item="$module:$basename:$target";
						$$self{'MainScan'}->Log->Debug("QueueTargets: OnePerHost Item $item") if ($$self{'MainScan'}->Debug>1);
						next if ($self->singleScanned("$module:$target"));
					}
					$$self{'MainScan'}->Log->Debug("QueueTargets: Checking if we can add $item") if ($$self{'MainScan'}->Debug>1);
					if ($self->FreeToQueue($item)){
						$$self{'MainScan'}->Log->Debug("QueueTargets: Queuing $item") if ($$self{'MainScan'}->Debug>1);
						push @{$$self{'Queue'}}, $item;
						if ($self->Module($module)->SingleScan){
							push @{$$self{'singleScanned'}}, "$module:$target";
						}
					}
				}
			}
		}
	}
}

sub FreeToQueue {
	my $self=shift();
	my $target=shift();
	$$self{'MainScan'}->Log->Debug("FreeToQueue: Checking $target") if ($$self{'MainScan'}->Debug>1);
	for my $item (@{$$self{'Queue'}}){
		$$self{'MainScan'}->Log->Debug("FreeToQueue: Checking $item ($target)") if ($$self{'MainScan'}->Debug>1);
		if ($target eq $item){
			$$self{'MainScan'}->Log->Debug("FreeToQueue: NO: $item already Queued") if ($$self{'MainScan'}->Debug>2);
			return 0;
		}
	}
	for my $item (@{$$self{'Dispatched'}}){
		$$self{'MainScan'}->Log->Debug("FreeToQueue: Checking $item ($target)") if ($$self{'MainScan'}->Debug>1);
		if ($target eq $item){
			$$self{'MainScan'}->Log->Debug("FreeToQueue: NO: $item already Dispatched") if ($$self{'MainScan'}->Debug>2);
			return 0;
		}
	}
	return 1;
}

sub RemoveFromQueue {
	my $self=shift();
	my $target=shift();
	my @newQueue;
	for my $item (@{$$self{'Queue'}}){
		if ("$target" ne "$item"){
			push @newQueue, $item;
		}
	}
	@{$$self{'Queue'}}=@newQueue;
	push @{$$self{'Dispatched'}}, $target;
}

sub StartedAnotherThread {
	my $self=shift();
	my $reset=shift();
	my $a=$$self{'startedAnotherThread'};
	$$self{'startedAnotherThread'}=0 if ($reset);
	return $a;
}

sub Idle {
	my $self=shift();
	if ($$self{'Used'}==0){
		return 1;
	}
	return 0;
}

sub MainScan {
	my $self=shift();
	return $$self{'MainScan'};
}

sub FreeBudget {
	my $self=shift();
	return ($$self{'Budget'} - $$self{'Used'});
}

sub AddCost {
	my $self=shift();
	my $cost=shift();
	if ($cost && $cost !~ /\D/){
		$$self{'Used'} += $cost;
	}
	my $free=($$self{'Budget'} - $$self{'Used'});
	return $free;
}

sub RemoveCost {
	my $self=shift();
	my $cost=shift();
	if ($cost && $cost !~ /\D/){
		$$self{'Used'} -= $cost;
	}
	my $free=($$self{'Budget'} - $$self{'Used'});
	return $free;
}

sub Budget {
	my $self=shift();
	my $newBudget=shift();
	if (defined($newBudget) && ($newBudget =~ /^\d+$/)){
		$$self{'Budget'}=$newBudget;
	}
	return $$self{'Budget'};
}

sub LoadTarget {
	my $self=shift();
	my $newTarget=shift();
	if (defined($newTarget) && ($newTarget =~ /^\d+$/)){
		$$self{'LoadTarget'}=$newTarget;
	}
	return $$self{'LoadTarget'};
}

sub ModulesWatching {
	my $self=shift();
	my $file=shift();
	return undef if (!defined($file));
	return @{$$self{'WatchFiles'}{'Watching'}{$file}};
}

sub FileUpdated {
	my $self=shift();
	my $file=shift();
	return undef if (!defined($file));
	my $modified=$self->FileModifiedTime($file);
	$modified=1 if (!defined($modified));
	if ($modified != $$self{'WatchFiles'}{'Data'}{'Modified'}{$file}){
		return 1;
	}
	return 0;
}

sub FileModifiedTime {
	my $self=shift();
	my $file=shift();
	return undef if (!defined($file));
	my @stat=stat($file);
	return $stat[9];
}

sub WatchFiles {
	my $self=shift();
	return @{$$self{'WatchFiles'}{'List'}};
}

sub Costs {
	my $self=shift();
	return @{$$self{'Modules'}{'Loaded'}{'Costs'}};
}

sub ModulesCosting {
	my $self=shift();
	my $cost=shift();
	return undef if (!defined($cost) || ($cost !~ /^\d+$/));
	return @{$$self{'Modules'}{'Loaded'}{'Cost'}{$cost}};
}

sub Modules {
	my $self=shift();
	return @{$$self{'Modules'}{'Loaded'}{'Names'}};
}

sub FailedModules {
	my $self=shift();
	return @{$$self{'Modules'}{'Failed'}};
}

sub DisableModule {
	my $self=shift();
	my $module=shift();
	$$self{'Modules'}{'Disabled'}{$module}=1;
	return 0;
}

sub EnableModule {
	my $self=shift();
	my $module=shift();
	$$self{'Modules'}{'Disabled'}{$module}=undef;
	return 0;
}

sub ModuleDisabled {
	my $self=shift();
	my $module=shift();
	return 1 if ($$self{'Modules'}{'Disabled'}{$module});
	return 0;
}

sub ModifyModule {
	my $self=shift();
	my $modifiedObject=shift();
	my $index=shift();
	@{$$self{'Modules'}{'Loaded'}{'Objects'}}[$index]=$modifiedObject;
	return 0;
}

sub ModuleIndex {
	my $self=shift();
	my $module=shift();
	return undef if (!defined($module));
	for (my $i=0; $i<=$#{$$self{'Modules'}{'Loaded'}{'Names'}}; $i++){
		if ("$module" eq "${$$self{'Modules'}{'Loaded'}{'Names'}}[$i]"){
			return $i;
		}
	}
	return undef;
}

sub Module {
	my $self=shift();
	my $module=shift();
	return undef if (!defined($module));
	my $i=$self->ModuleIndex($module);
	if (defined($i)){
		return @{$$self{'Modules'}{'Loaded'}{'Objects'}}[$i];
	}
}

sub ProcessNeetShellInteractions {
	# Should modify this to use a FIFO
	my $self=shift();
	my $file = $$self{'MainScan'}->ControlDirectory . "/interaction";
	if (-f $file){
		my $modified=$self->FileModifiedTime($file);
		if ($modified != $$self{'InteractionFileModifiedTime'}){
			# File has been modified. Read the request
			my $freebudget=($$self{'Budget'} - $$self{'Used'});
			my @f=$$self{'MainScan'}->ReadFile($file);
			for my $line (@f){
				chomp $line;
				if ($line =~ /^\d+$/){
					if ($$self{'Budget'} != $line){
						$$self{'MainScan'}->Log->Warn("*** GSM Performance Budget changed to $line ***\n");
						$$self{'Budget'}=$line;
					}
					last;

				} elsif ($line =~ /show/){
					$$self{'MainScan'}->Log->Info("*** GSM Performance Budget: $freebudget free out of $$self{'Budget'} ***");
					$modified=0;
					last;

				} elsif ($line =~ /pause/){
					unlink $file;
					kill (2, $$self{'UIPID'});
					last;

				} elsif ($line =~ /gsmsummary/){
					$self->GSMSummary;
					$modified=0;
					last;

				} elsif ($line =~ /debug/){
					if ($$self{'MainScan'}->Debug>2){
						$$self{'MainScan'}->Debug(0);
					} else {
						$$self{'MainScan'}->Debug(($$self{'MainScan'}->Debug + 1));
					}
					$$self{'MainScan'}->Log->Info("*** Setting Debug level to " . $$self{'MainScan'}->Debug . " ***\n");
					$modified=0;
					last;

				} elsif ($line =~ /^load \d+/){
					my ($junk,$target)=split " ", $line; chomp $target;
					if ($$self{'LoadTarget'} != $target){
						$$self{'MainScan'}->Log->Warn("*** Load Average target changed to $target ***\n");
						$$self{'LoadTarget'}=$target;
					}
					$modified=0;
					last;

				} elsif ($line =~ /^disable \w+/){
					my ($junk,$module)=split " ", $line; chomp $module;
					$self->DisableModule($module);
					$$self{'MainScan'}->Log->Warn("Disabling GSM Module $module");
					$modified=0;
					last;

				} elsif ($line =~ /^enable \w+/){
					my ($junk,$module)=split " ", $line; chomp $module;
					$self->EnableModule($module);
					$$self{'MainScan'}->Log->OK("Enabling GSM Module $module");
					$modified=0;
					last;

				} elsif ($line =~ /queue/){
					$$self{'MainScan'}->Log->Info("*** Current Queue (Module:SourceFile:Host:Service) ***","PRINTONLY");
					for my $item (@{$$self{'Queue'}}){
						my ($module,$junk)=split (":", $item, 2);
						my $cost=$self->Module($module)->Cost;
						print "$item (Cost: $cost)\n";
					}
					$$self{'MainScan'}->Log->Info("***    Items at the TOP will be processed first    ***","PRINTONLY");
					$$self{'MainScan'}->Log->Info("***   ***   ***   ***            ***   ***   ***   ***","PRINTONLY");
					$$self{'MainScan'}->Log->Info("*** GSM Performance Budget: $freebudget free out of $$self{'Budget'} ***","PRINTONLY");
					$modified=0;
					last;

				} elsif ($line =~ /running/){
					print "*** Running Module Summary ***\n";
					for my $id (@{$$self{'Threads'}{'IDs'}}){
						print "Module: $$self{'Threads'}{$id}{'module'} -> $$self{'Threads'}{$id}{'target'} Cost: $$self{'Threads'}{$id}{'cost'}\n";
					}
					print "*** Budget used: $$self{'Used'} out of $$self{'Budget'} ***\n";
					$modified=0;
					last;

				} elsif ($line =~ /^incinstance/){
					chomp $line;
					my ($junk,$module)=split " ", $line;
					my $index=$self->ModuleIndex($module); my $moduleObject=$self->Module($module);
					if (defined($index)){
						my $instances=$moduleObject->MaxInstances;
						# Don't bother increasing it if it's already unlimited
						if ($instances > 0){
							$instances++; $$moduleObject{'MaxInstances'}=$instances;
							$$self{'MainScan'}->Log->Info("*** Increasing MaxInstances for $module module to $instances ***");
							$self->ModifyModule($moduleObject,$index);
						}
					}
					$modified=0;
					last;

				} elsif ($line =~ /^decinstance/){
					chomp $line;
					my ($junk,$module)=split " ", $line;
					my $index=$self->ModuleIndex($module); my $moduleObject=$self->Module($module);
					if (defined($index)){
						my $instances=$moduleObject->MaxInstances;
						# Don't allow decreasing it to 0, as that means "unlimited"
						if ($instances > 1) {
							$instances--; $$moduleObject{'MaxInstances'}=$instances;
							$$self{'MainScan'}->Log->Info("*** Decreasing MaxInstances for $module module to $instances ***");
							$self->ModifyModule($moduleObject,$index);
						}
					}
					$modified=0;
					last;
				}

			}
			unlink $file if ($modified == 0);
			$$self{'InteractionFileModifiedTime'}=$modified;
		}
	}
}

sub GSMSummary {
	my $self=shift();
	print "*** Modules ***\n";
	for my $module (@{$$self{'Modules'}{'Loaded'}{'Names'}}){
		print "Loaded module $module\n";
	}
	print "*** Watch Files ***\n";
	for my $file (@{$$self{'WatchFiles'}{'List'}}){
		print "--- $file---\n";
		for my $module (@{$$self{'WatchFiles'}{'Watching'}{$file}}){
			print "  -> watched by $module\n";
		}
	}
}

sub LoadModules {
	no warnings;
	my $self=shift();
	my $ModLoaded;


	if ($$self{'MainScan'}->LimitGsms){
		# Warn if the user specified some limited GSMs and then one or more don't exist
		# (Typos on the command line etc)
		find(\&_list_modules, "$$self{'ModuleDir'}");
		for my $limitedModule ($$self{'MainScan'}->LimitedGsms){
			my $warn=1;
			for my $module (@{$$self{'Modules'}{'Found'}}){
				if ($module eq $limitedModule){
					$warn=0;
					last;
				}
			}
			if ($warn){
				$$self{'MainScan'}->Log->Error("GSM \"$limitedModule\" doesn't exist\n");
			}
		}
	}
	find(\&_load_module, "$$self{'ModuleDir'}");
	return 0;

	sub _list_modules {
		my $module=$_;
		if (( -f $module ) && ( $module =~ /.gsm$/ )){
			$module =~ s/\.gsm$//;
			push @{$$self{'Modules'}{'Found'}}, $module;
		}
	}

	sub _load_module {
		
		my $module=$_;
		if (defined($module) && ( -f $module ) && ( $module =~ /.gsm$/ )){
			my $filename = $module; $module =~ s/\.gsm$//;
			if ($$self{'MainScan'}->LimitGsms){
				my $match=0;
				for my $limitedModule ($$self{'MainScan'}->LimitedGsms){
					if ($limitedModule eq $module){
						$match=1;
					}
				}
				if (!$match){
					return 0;
				}
			}
			for my $disabledModule ($$self{'MainScan'}->DisabledGsms){
				if ($disabledModule eq $module){
					return 0;
				}
			}
	
			$ModLoaded=1;
			eval {
					require "$$self{'ModuleDir'}/$filename";
			} || _NotLoaded();
			if ($ModLoaded){
				my $mod=$module->new($$self{'MainScan'});
				if ($mod->Enabled){
					my $modname=$mod->Name;
					my $cost=$mod->Cost;
					push @{$$self{'Modules'}{'Loaded'}{'Names'}}, $modname;
					push @{$$self{'Modules'}{'Loaded'}{'Objects'}}, $mod;
					push @{$$self{'Modules'}{'Loaded'}{'Cost'}{$cost}}, $modname;
					my $exists=0;
					for my $cost (@{$$self{'Modules'}{'Loaded'}{'Costs'}}){
						if ($cost eq $mod->Cost){
							$exists=1;
							last;
						}
					}
					push @{$$self{'Modules'}{'Loaded'}{'Costs'}}, $mod->Cost if (!$exists);
					# Now sort the costs into descending order ({$b <=> $a} operator)
					my @sort=sort {$b <=> $a} @{$$self{'Modules'}{'Loaded'}{'Costs'}};
					@{$$self{'Modules'}{'Loaded'}{'Costs'}} = @sort;
					$#sort=-1;
					
					for my $file ($mod->Watching){
						# Allow reverse directory traversal into the results directory, but nowhere else
						$file =~ s/\.\.\/\.\.\///g;
						$file=$$self{'MainScan'}->ResultsDirectory . "/services/$file";
						push @{$$self{'Modules'}{'Loaded'}{'Watching'}{$modname}}, $file;
						addWatchFile($file,$modname);
					}

				}
			} else {
				if ($module){
					push @{$$self{'Modules'}{'Failed'}}, $module;
				}
			}
		}
	}

	sub _NotLoaded {
		# Module didn't load
		print $@;
		$ModLoaded=0;
	}

	sub addWatchFile {
		my $file=shift();
		my $module=shift();
		return undef if (!defined($module));
		$exists=0;
		for my $wf (@{$$self{'WatchFiles'}{'List'}}){
			if ("$wf" eq "$file"){
				$exists=1;
				last;
			}
		}
		if (!$exists){
			push @{$$self{'WatchFiles'}{'List'}}, $file;
			# Set it to 0 to force an initial read
			$$self{'WatchFiles'}{'Data'}{'Modified'}{$file}=0;
		}
		$exists=0;
		for my $watching (@{$$self{'WatchFiles'}{'Watching'}{$file}}){
			if ("$watching" eq "$module"){
				$exists=1;
				last;
			}
		}
		push @{$$self{'WatchFiles'}{'Watching'}{$file}}, $module if (!$exists);
	}
}

1;

