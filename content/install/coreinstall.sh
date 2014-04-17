#!/bin/bash

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


# This program does the installation of the neet core. It should only be
# invoked by the neet installer or neet-update.

if [ -z $NEETINSTALLER ] && [ -z $INVOKEDBYNEETUPDATE ]; then
	echo "This script should NOT be inkoved manually! Leave it alone!"
	exit 1
fi

. ./install/installsupport

# Base permissions
umask 022

for directory in bin etc pkg/bin doc core/update/build; do
	mkdir -p "${NEET}/$directory"
done

if [ ! -d "${NEET}/bin" ]; then
	echo "Couldn't create the Neet home directory ${NEET}. Quitting."
	touch install/error
	exit 1
fi

# Config information
echo "neetbase=${NEET}" > "${CONFDIR}/locations"
cat install/locations >> "${CONFDIR}/locations"
cp install/installsupport install/githubVersion "${NEET}/core/"

cd main

for subdir in bin etc; do
	cp -R "${subdir}" "${NEET}/"
done

# Perl modules
cp -R JR Neet "${NEET}/core/"

# Now, set up links to the directories in the main $PATH
for bin in neet neet-update; do
	ln -sf ${NEET}/bin/${bin} /usr/bin/${bin} 2>/dev/null
done

# Somewhere for the documentation to go
cp ../doc/*.html ${NEET}/doc/

# Now the man pages
MANIN=0
if [ -f /etc/manpath.config ]; then
	for path in `grep ^MANDATORY_MANPATH /etc/manpath.config | grep /usr/local/ | awk {print'$2'}`; do
		if [ -d "$path/man1/" ]; then
			cp man/*.gz ${path}/man1/
			MANIN=1
			MANPATH=$path
			break
		fi
	done
else
	for path in `echo $MANPATH | sed -e 's/:/ /g'`; do
		if [ -d "$path/man1" ]; then
			cp man/*.gz ${path}/man1/
			MANIN=1
			MANPATH=$path
			break
		fi
	done
fi
if [ $MANIN -eq 0 ]; then
	# Force install
	path=/usr/share/man
	mkdir -p /usr/share/man/man1
	cp man/*.gz ${path}/man1/
	[ $? -eq 0 ] && MANIN=1 && MANPATH=$path
fi

if [ $MANIN -eq 1 ]; then
	echo "Man pages have been installed into $MANPATH/man1"
fi

newVersion neet $VERSION
# Ensure that the location information is up to date
${NEET}/bin/updateLocations

chown -R root.root "$NEET"
chmod -R go-w "$NEET"
chmod -R +X "$NEET"
chmod 755 ${NEET}/bin/*

