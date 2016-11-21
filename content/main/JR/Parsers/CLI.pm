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

# Command Line Parser
package JR::Parsers::CLI;

sub new {
	my $pkg=shift();
	my $struct=shift();
	my (%CLI,@cli,@allowed,@needsparam,@multis,@params,%Short,%Map);

	#Parse the command line structure
	for (my $a=0; $a<length($struct); $a++){
		my $opt=substr($struct,$a,1);
		my $next=substr($struct,$a+1,1);
		if ($opt =~ /[a-z|A-Z]/){
			push @allowed, $opt;
			if ($next eq ":"){
				push @needsparam, $opt;
				$a++ if ($a<length($struct));
			} elsif ($next eq "@"){
				push @needsparam, $opt;
				push @multis, $opt;
				$a++ if ($a<length($struct));
			}
		}
	}

	$CLI{'allowed'}=\@allowed;
	$CLI{'multis'}=\@multis;
	$CLI{'args'}=\@cli;
	$CLI{'struct'}=$struct;
	$CLI{'params'}=\@params;
	$CLI{'needsparam'}=\@needsparam;
	$CLI{'Short'}=\%Short;
	$CLI{'Map'}=\%Map;

	my $object=\%CLI;
	bless $object, $pkg;

	return $object;
}

sub ListArgs {
	my $self=shift();
	return @{$$self{'args'}};
}

sub ListAllowed {
	my $self=shift();
	return @{$$self{'allowed'}};
}

sub ListNeedParams {
	my $self=shift();
	return @{$$self{'needsparam'}};
}

sub ListNoNeedParams {
	my $self=shift();
	my @opts;
	for my $opt (@{$$self{'allowed'}}){
		push @opts, $opt if (!$self->__needsParam($opt));
	}
	return @opts;
}

sub ListParams {
	my $self=shift();
	return @{$$self{'params'}};
}

sub LongShortMap {
	my $self=shift();
	while (my $Long=shift(@_)){
		my $Short=shift(@_);
		${$$self{'Map'}{'Long'}{$Long}}=$Short;
		${$$self{'Map'}{'Short'}{$Short}}=$Long;
	}
}

sub Got {
	my $self=shift();
	my $var=shift();

	if (defined(${$$self{'Short'}{$var}{'set'}})){
		return 1;
	}
	return 0;
}

sub CommandLine {
	my $self=shift();
	my $commandLine;
	for my $_arg (@{$$self{'args'}}){
		$commandLine .= " $_arg";
	}
	$commandLine =~ s/^ //g if ($commandLine);
	return $commandLine;
}

sub Value {
	my $self=shift();
	my $var=shift();

	if (defined(${$$self{'Short'}{$var}{'value'}})){
		return ${$$self{'Short'}{$var}{'value'}};
	}
	return undef;
}

sub Process {
	my $self=shift();
	@{$$self{'args'}}=@_;
	return $self->__parse;
}

sub ValuesOf {
	my $self=shift();
	my $var=shift();
	my @list;
	if ($self->__isMulti($var)){
		for my $a (@{$$self{'Multi'}{$var}}){
			push @list, $a;
		}
		return @list;
	}
	return undef;
}

# ******************

sub __parse {
	my $self=shift();
	my @args=@{$$self{'args'}};
	while (my $argument=shift(@args)){
		my $arg=$argument;
		$arg =~ s/^\-+//g;
		my ($short,$value);

		# First, map longs to shorts
		if ($self->__isLong($argument)){
			# This may have a parameter
			my ($long,$_value)=split "=", $arg;
			# Check in the map if we have it
			
			if (defined(${$$self{'Map'}{'Long'}{$long}})){
				my $_short=${$$self{'Map'}{'Long'}{$long}};
				$short=$_short; $arg=$short;
				$value=$_value if ($_value);
			} else {
				die ("JR::Parsers::CLI -> Invalid argument $argument\n");
			}
		}

		if ($self->__isShort($argument)) {
			$short=substr($arg,0,1);
		}

		if ($short){
			if (!$self->__isAllowed($short)){
				die ("JR::Parsers::CLI -> Invalid argument $argument\n");
			}
			${$$self{'Short'}{$short}{'set'}}=1;
			if ($self->__needsParam($short)){
				# Get the parameter
				if (defined($value)){
					${$$self{'Short'}{$short}{'value'}}=$value;
					if ($self->__isMulti($short)){
						push @{$$self{'Multi'}{$short}}, $value;
					}
				} else {
					if (length($arg)>1){
						$value=substr($arg,1,length($arg)-1);
						${$$self{'Short'}{$short}{'value'}}=$value;
						if ($self->__isMulti($short)){
							push @{$$self{'Multi'}{$short}}, $value;
						}
					} else {
						$value=shift(@args);
						if (defined($value) && $self->__isParam($value)){
							${$$self{'Short'}{$short}{'value'}}=$value;
							if ($self->__isMulti($short)){
								push @{$$self{'Multi'}{$short}}, $value;
							}
						} else {
							die ("JR::Parsers::CLI -> Argument $argument requires a parameter\n");
						}
					}
				}
			} else {
				# Doesn't need a parameter. Check for a cluster of args
				if (length($arg)>1){
					for (my $a=0; $a<length($arg); $a++){
						my $short=substr($arg,$a,1);
						if (!$self->__isAllowed($short)){
							die ("JR::Parsers::CLI -> Invalid argument $short\n");
						}
						${$$self{'Short'}{$short}{'set'}}=1;
						if ($self->__needsParam($short)){
							# Uh-oh
							if ($a == length($arg)-1){
								$value=shift(@args);
								if (defined($value) && $self->__isParam($value)){
									${$$self{'Short'}{$short}{'value'}}=$value;
								} else {
									die ("JR::Parsers::CLI -> Argument $short requires a parameter\n");
								}
							} else {
								die ("JR::Parsers::CLI -> Argument $short requires a parameter\n");									
							}
						}
					}
				}
			}
		}

		if ($self->__isParam($argument)){
			push @{$$self{'params'}}, $arg;
		}
	}
}

sub __needsParam {
	my $self=shift();
	my $short=shift();
	for my $opt (@{$$self{'needsparam'}}){
		if ($opt eq $short){
			return 1;
		}
	}
	return 0;
}

sub __isMulti {
	my $self=shift();
	my $short=shift();
	for my $opt (@{$$self{'multis'}}){
		if ($opt eq $short){
			return 1;
		}
	}
	return 0;
}

sub __isAllowed {
	my $self=shift();
	my $short=shift();
	for my $opt (@{$$self{'allowed'}}){
		if ($opt eq $short){
			return 1;
		}
	}
	return 0;
}
sub __isLong {
	my $self=shift();
	my $arg=shift();
	if ($arg =~ /^--/){
		return 1;
	}
	return 0;
}

sub __isShort {
	my $self=shift();
	my $arg=shift();
	if ($arg !~ /^--/ && $arg =~ /^-/){
		return 1;
	}
	return 0;
}

sub __isParam {
	my $self=shift();
	my $arg=shift();
	if ($arg !~ /^-/){
		return 1;
	}
	return 0;
}

1;


__END__

=head1 NAME

JR::Parsers::CLI - A PERL module for parsing command line options. 

=head1 SYNOPSIS

	use JR::Parsers::CLI;

	# Create a CLI object reference.

	my $cli=JR::Parsers::CLI->new('arguments');

	# Map long alternatives to short options

	$cli->LongShortMap ('verbose' => 'v', 'stdout' => 's');

	# Load the command line into the object and parse it

	$cli->Process(@ARGV);

	# Did we get -v (or --verbose)?

	print "yay!\n" if ($cli->Got('v'));

	# What was the value of "f"

	print "F is " . $cli->Value('f') . "\n" if ($cli->Got('f'));

	# List of parameters

	print join "\n", $cli->ListParams;

	# All values specified with argument '-f'

	print join "\n", $cli->ValuesOf('f');
	

=head1 DESCRIPTION

JR::Parsers::CLI is a module for parsing command-line options. It provides an object-oriented
interface to getopt-like command-line parsing, allowing for both short and long, POSIX style
command-line options and parameters. The command-line options can be passed in any order, as long as
any arguments that require parameters are immediately followed by them.

There are a few differences to Getopt here, which is - of course - why JR::Parsers::CLI was written.

The first difference is that the command-line is case-sensitive in JR::Parsers::CLI, while it is
not in Getopt.

Another difference is that this module handles both short and long argument forms, whereas two separate
modules are required for your program to support both long and short versions using Getopt, if it is
possible at all.

The last difference is that this module provides a nice object-oriented approach to command-line
parsing.

=head1 EXAMPLES

Consider a program that uses any of the following options: -a -b -f -r -R -v.
The -r and -f parameters require parameters to be passed to them. -f can
be specified multiple times. A hostname parameter is also required to be passed
to the program, but does not need a flag to indicate this.

The constructor would take the following form:

	my $cli=JR::Parsers::CLI->new('abf@r:Rv');

Suppose that it was also required that "--verbose" had the same effect as '-v', and that
"--repeats" had the same effect as '-r'. The LongShortMap() method would be used to achieve this.

	$cli->LongShortMap ('verbose'=>'v','repeats'=>'r');

Note the lack of leading "-" symbols. Short-version grouping is allowed, and so any of the following
argument arrangements are equally valid:


	prog -a -b -f file1 -r 2 --verbose hostname

	prog -abvf file1 hostname -r2

	qprog hostname -a -bv -f file1 --repeats=2

*** Note - the command-line options ARE CASE-SENSITIVE.

Now the command line parser is ready to parse the command-line.

	$cli->Process(@ARGV);

Reading what was passed on the command-line is simple. To check if '-v' (or '--verbose') was passed:

	print "Verbose\n" if ($cli->Got('v'));

The value of "-r" or "--repeats" is read by something like:

	print $cli->Value('r') . " repeats\n" if ($cli->Got('f'));

To get the hostname (or any number of parameters passed without explicit flags):

	print join "\n", $cli->ListParams;

To list all values passed via the -f parameter:

print join "\n", $cli->ValuesOf('f');

=head1 METHODS

=item new()

	This method is the constructor, and creates the object. It takes one argument, which is
	a scalar string representing all the parameters that can be accepted on the command line
	(in short form). For example, if the argument "-a" can be accepted, then the string
	should contain the letter 'a'.

	If the "-a" argument requires a parameter, then a colon should immediately follow the
	letter 'a' in the argument string. If the "-a" argument can be specified multiple times,
	then an "@" symbol should immediately follow the 'a' instead of the colon.

=item Process(@ARGV)

	Process() loads the command-line into the object and parses it. Any errors in the command-line
	will be flagged here. Typical errors thrown include usage of arguments that were not declared
	in the constructor, and not passing parameters to arguments that require them.




=head1 AUTHOR

	JR - jonny.hightower@gmail.com

