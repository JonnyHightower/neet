#!/bin/bash

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

if [ `id -u` -ne 0 ]; then
	echo "You must be root to remove Neet."
	exit 1
fi

PREFIX=/opt
export PREFIX
export NEET="${PREFIX}/neet"
export CONFDIR="${NEET}/etc"
export CONFIG="${CONFDIR}/neet.conf"
export INST="$PWD"

INSTALLED=1
DOUNINSTALL=1

# Import some functions
if [ -f "${NEET}/core/installsupport" ]; then
	. "${NEET}/core/installsupport"
else
	. install/installsupport
fi

if [ ! -d "${NEET}/bin" ]; then
	INSTALLED=0
fi

if [ -z $NEETINSTALLER ]; then
	# Standalone uninstall
	if [ $INSTALLED -eq 0 ]; then
		echo "Neet installation not found in $PREFIX/. Can't uninstall."
		exit 1
	fi
	echo "This will remove Neet and its components. Are you sure? [y/N]"
	read -sn1 r
	if [ -z "$r" ] || [ "$r" != "y" ]; then
		echo "Uninstall aborted by user."
		exit 0
	fi

else
	# Being run as part of the neet installer
	if [ $INSTALLED -eq 0 ]; then
		echo "No previous NEET installation found."
		DOUNINSTALL=0
	else
		echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
		echo
		echo "A previous Neet installation was found, and will be removed first. This"
		echo "will remove the previous installation of Neet and all its components."
		echo "Are you sure? [y/N]"
		read -sn1 r
		if [ -z "$r" ] || [ "$r" != "y" ]; then
			echo "Uninstall aborted by user. Neet installation will not continue."
			exit 0
		fi
	fi
fi

if [ $DOUNINSTALL -eq 1 ]; then
	echo "Uninstalling"
	for bin in neetsh neet neet-maint gethash mimikatz neet-update; do
		[ -s "/usr/bin/$bin" ] && rm "/usr/bin/$bin" -f
		# Old versions of neet
		[ -s "/usr/local/sbin/$bin" ] && rm "/usr/local/sbin/$bin" -f
	done

	# Preserve config in case we want to use it in future
	if [ -f "${CONFIG}" ]; then
		mv "${CONFIG}" ${HOME}/neet.conf.saved
	fi

	# Do the main deed
	rm -rf "${NEET}"

  # Old versions of neet
  rm -rf /etc/neet/

	# Now the man pages
	MANIN=0
	if [ -f /etc/manpath.config ]; then
		for path in `grep ^MANDATORY_MANPATH /etc/manpath.config | grep /usr/local/ | awk {print'$2'}`; do
			if [ -d "$path" ]; then
				MANIN=1
				manpath=$path
				break
			fi
		done
	else
		for path in `echo $MANPATH | sed -e 's/:/ /g'`; do
			if [ -d "$path" ]; then
				MANIN=1
				manpath=$path
				break
			fi
		done
	fi
	if [ $MANIN -eq 0 ]; then
		manpath=/usr/share/man
		MANIN=1
	fi

	if [ $MANIN -eq 1 ]; then
		for man in neet.1.gz neetsh.1.gz neet-qs.1.gz; do
			rm -f ${manpath}/man1/${man}
		done
	fi

  # Older versions of neet stored man pages in /usr/share/man. Remove them in case
  # this process picked a different man path.
  rm -f /usr/share/man/man1/neet*

	echo "Neet has been removed from the system"
fi

