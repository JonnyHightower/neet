#!/bin/bash

# Installs PERL dependencies for NEET. DBD-Sybase probably won't build unless you have the freetds libraries installed. It just means you
# won't be able to use my iShell MS-SQL direct shell connector.

wd=$PWD
FORCE_INSTALL="NONE"
NO_TEST="Net-Pcap- DBD-Sybase"
PREFIX=$1
[ ! -d "${PREFIX}" ] && PREFIX=/usr/local

# Set up any environment stuff here
if [ -f /usr/include/sybdb.h ]; then
	export SYBASE=/usr
else
	export SYBASE=/usr/local
fi

for mod in Net-IP Digest-SHA Digest-HMAC Net-SSLeay NetAddr-IP XML-Twig XML-Parser Net-RawIP Net-Pcap- NetPacket Net-PcapUtils Net-ARP DBI DBD-Sybase IO-Socket-SSL Net-DNS Net-SSH; do
	force=0
	for fp in $FORCE_INSTALL; do
		if [ "$fp" == "$mod" ]; then
			force=1
			echo "Force installing $mod"
		fi
	done
	test=1
	for fp in $NO_TEST; do
		if [ "$fp" == "$mod" ]; then
			test=0
		fi
	done
	pmod=`echo $mod | sed -e 's/-/::/g'`
	pmod=`echo $pmod | sed -e 's/::$//'`
	if [ $force == 0 ] && perl -e "use $pmod" 2>/dev/null; then
		echo "$pmod is already installed"
		continue
	fi
	echo
	echo "*****************************************"
	echo "*** Building module $pmod"
	echo "*****************************************"
	echo

	# Extract the tarball
	dir=`tar tzf ${mod}*gz | head -n1 | sed -e 's?/$??'`
	tar xzf ${mod}*gz
	installed=0
	cd "$dir"
	if [ -x neet-prep.sh ]; then
		./neet-prep.sh $PREFIX
	fi
	if [ -f Makefile.PL ]; then
		perl Makefile.PL
	fi
	if [ -x neet-makeprep.sh ]; then
		./neet-makeprep.sh $PREFIX
	fi
	if [ -f Makefile ] && make; then
		ok=0
		if [ "$test" == "1" ]; then
			echo
			echo "  *****************************************"
			echo "    *** Testing $pmod"
			echo "  *****************************************"
			echo
			if make test; then
				echo
				echo "  *****************************************"
				echo "   $pmod Tested OK"
				echo "  *****************************************"
				echo
				ok=1
			else
				echo
				echo "  *****************************************"
				echo "   $pmod Tests FAILED"
				echo "  *****************************************"
				echo
			fi
		else
			ok=1
		fi
		if [ "$ok" == "1" ]; then
				echo
				echo "  *****************************************"
				echo "   Installing $pmod"
				echo "  *****************************************"
				echo
			make install && installed=1
		else
			echo
			echo "  *****************************************"
			echo "    $pmod failed its build tests. Not installing"
			echo "  *****************************************"
			echo
		fi
	fi

	cd "$wd"
	if [ $installed -eq 1 ]; then
			echo
			echo "  *****************************************"
			echo "   $pmod was installed OK"
			echo "  *****************************************"
			echo

		rm -r "$dir"
	else
			echo
			echo "  *****************************************"
			echo "   $pmod installation FAILED"
			echo "  *****************************************"
			echo

	fi

done
