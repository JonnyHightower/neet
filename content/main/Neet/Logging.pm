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

# Logging.pm

# Logging for Neet
# Jonathan Roach
package Neet::Logging;

use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;
use Fcntl ':flock';

sub new {
	my $pkg=shift();
	my %Logger;
	$Logger{'LogFile'}="Logfile";
	$Logger{'Logging'}=0;
	$Logger{'AltColour'}=0;
	$Logger{'Linestamp'}=0;
	my $self=\%Logger;
	bless $self, $pkg;
	return $self;
}

sub LogFile {
	my $self=shift();
	my $file=shift();
	if (!$file){
		return $$self{'LogFile'};
	} else {
		$$self{'LogFile'}=$file;
		return 1;
	}
}

sub AltColour {
	my $self=shift();
	my $alt=shift();
	if (!defined($alt)){
		return $$self{'AltColour'};
	} else {
		$$self{'AltColour'}=$alt;
		return 1;
	}
}

sub Linestamp {
	my $self=shift();
	my $alt=shift();
	if (!defined($alt)){
		return $$self{'Linestamp'};
	} else {
		$$self{'Linestamp'}=$alt;
		return 1;
	}
}

sub OpenLog {
	my $self=shift();
	my $direct=shift();
	my $FH;
	if (open($FH,">>$$self{'LogFile'}")){
		$$self{'LOGHANDLE'}=$FH;
		$$self{'Logging'}=1;
		if (!$direct){
			$self->Log ("- - - - - - - - - - - -\n");
			$self->Log ("Log opened by PID $$\n");
		}
		return 1;
	} else {
		return 0;
	}
}

sub CloseLog {
	my $self=shift();
	my $direct=shift();
	if ($$self{'Logging'}){
		if (!$direct){
			$self->Log ("Log closed\n");
		}
		my $FH=$$self{'LOGHANDLE'};
		close $FH;
		return 1;
	}
	return 0;
}

sub Logging {
	my $self=shift();
	return $$self{'Logging'};
}

sub LogNoStamp {
	my $self=shift();
	return 0 if (!$$self{'Logging'});
	my $entry=shift();
	my $FH=$$self{'LOGHANDLE'};
	chomp $entry; $entry .= "\n";
	print $FH $entry;
	return 1;
}

sub Log {
	my $self=shift();
	my $message=shift();
	return 0 if (!$$self{'Logging'});
	$message =~ s/--+//g;
	chomp $message; $message .= "\n";
	my $FH=$$self{'LOGHANDLE'};
	my $entry=localtime() . ": $message";
	flock($FH,LOCK_EX);
	print $FH $entry;
	flock($FH,LOCK_UN);
	return 1;
}

sub Error {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[ERROR] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print STDERR localtime() . " ERROR: $text";
		} else {
			print STDERR "ERROR: $text";
		}
	}
}

sub Debug {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[DEBUG] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print YELLOW localtime() . " [DEBUG] $text";
		} else {
			print YELLOW "[DEBUG] $text";
		}
	}
}

sub Memo {
	my $self=shift();
	my $text=shift();
	$self->Log("[MEMO] $text");
}

sub Warn {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[WARN] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print RED localtime() . " $text";
		} else {
			print RED "$text";
		}
	}
}

sub Vuln {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[VULN] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print RED localtime() . " [VULN]*** -> $text";
		} else {
			print RED "[VULN]*** -> $text";
		}
	}
}

sub Issue {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[ISSUE] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print RED localtime() . " [ISSUE] -> $text";
		} else {
			print RED "[ISSUE] -> $text";
		}
	}
}

sub Comp {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[COMP] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print RED localtime() . " [COMP]*** -> $text";
		} else {
			print RED "[COMP]*** -> $text";
		}
	}
}
	
sub OK {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[OK] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print GREEN localtime() . " $text";
		} else {
			print GREEN "$text";
		}
	}
}

sub Info {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[INFO] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'AltColour'}==0){
			if ($$self{'Linestamp'}){
				print WHITE localtime() . " $text";
			} else {
				print WHITE "$text";
			}
		} else {
			if ($$self{'Linestamp'}){
				print BLACK localtime() . " $text";
			} else {
				print BLACK "$text";
			}
		}
	}
}

sub Status {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[STAT] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print BLUE localtime() . " $text";
		} else {
			print BLUE "$text";
		}
	}
}

sub Alert {
	my $self=shift();
	my $text=shift();
	my $direct=shift();
	my ($print,$log)=(1,1);
	$print=0 if ($direct && "$direct" eq "LOGONLY");
	$log=0 if ($direct && "$direct" eq "PRINTONLY");
	$self->Log("[ALERT] $text") if ($log);
	chomp $text; $text .= "\n";
	if ($print){
		if ($$self{'Linestamp'}){
			print RED localtime() . " [ALERT] $text";
		} else {
			print RED "[ALERT] $text";
		}
	}
}

sub Exec {
	my $self=shift();
	my $text=shift();
	$self->Log("[EXEC] $text");
}

1;
