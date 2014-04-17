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

export VERSION=`cat VERSION`
export PREFIX=/opt

if [ ! -z $INVOKEDBYNEETUPDATE ] && [ $INVOKEDBYNEETUPDATE -eq 1 ]; then
	#echo "neet core installer invoked by neet-update. Performing quick install only."
	install/coreinstall.sh
	exit $?
fi

if [ `id -u` -ne 0 ]; then
	echo "You must be root to install Neet."
	exit 1
fi

if [ ! -d install ] || [ ! -d doc ] || [ ! -d main ] || [ ! -f install/installsupport ]; then
  echo "You must run this script from the topmost install directory."
   exit 1
fi


echo
echo "Neet Discovery Engine v${VERSION} - Installing..."
echo " - (c) Jonathan Roach 2008-2014"
echo
cat << EOF
  Copyright (C) 2008-2014 Jonathan Roach
  This program comes with ABSOLUTELY NO WARRANTY
  This is free software, and you are welcome to redistribute it
  under certain conditions; view the accompanying LICENSE for details.
EOF

export NEETINSTALLER=1
export UPDATEONLY=0
export NEET="${PREFIX}/neet"
export CONFDIR="${NEET}/etc"
export CONFIG="${CONFDIR}/neet.conf"
export INST=${PWD}

# Import some functions
. ./install/installsupport

[ -f install/error ] && rm install/error

# Is this a virgin install?
if [ -f ${NEET}/core/installsupport ]; then
	cat << EOM

  ** IMPORTANT **

  You are running the full installer, but outdated components can be
  updated more efficiently by periodically running neet-update. This
  installer will remove the existing neet installation and re-install
  it from scratch.

  If this is what you want type YES, otherwise I will run neet-update
  for you and update only the components which require updating.

  If you want to exit the installer without changing anything, type
  "exit" (without the quotes).

  >> If you just hit ENTER or type anything other than exit or YES,
  then I will run neet-update.

EOM
	read result
	if [ ! -z $result ]; then
		if [ "$result" == "exit" ]; then
			exit 0
		elif [ "$result" == "YES" ]; then
			UPDATEONLY=0
		else
			UPDATEONLY=1
		fi
	else
		UPDATEONLY=1
	fi
fi

if [ $UPDATEONLY -eq 1 ]; then
	echo "Running neet-update...."
	"${NEET}/bin/neet-update"
	exit 0
fi

# If this is Kali, do the prep
if isKali; then
  echo "Preparing Kali for neet"

  for package in libnet-arp-perl libnet-ip-perl libnetaddr-ip-perl libdbd-sybase-perl medusa winexe passing-the-hash\
		libnet-pcap-perl libnet1-dev libx11-protocol-perl bison ldap-utils libssl-dev libterm-readkey-perl\
		cmake flex libglib2.0-dev libgnutls26 libgnutls-dev libpcap0.8 libpcap-dev libgpgme11-dev uuid-dev; do
  	#echo
	  #echo "**** Installing $package ****"
  	apt-get -y install $package >/dev/null 2>&1
  	ERR=$?
  	if [ $ERR -ne 0 ]; then
  		echo "There was a problem installing $package."
	  	echo "Installation will terminate here."
		  exit 1;
	  fi
  done

elif isBacktrack; then
  # This is backtrack. Do the backtrack prep
  echo "Preparing Backtrack for neet"

  for package in libnet-arp-perl libnet-ip-perl libnetaddr-ip-perl libdbd-sybase-perl medusa\
		libnet-pcap-perl libnet1-dev libopenvasnasl2 libx11-protocol-perl bison ldap-utils \
		cmake flex libglib2.0-dev libgnutls26 libgnutls-dev libpcap0.8 libpcap-dev libgpgme11-dev uuid-dev; do

  	apt-get -y install $package >/dev/null 2>&1
	  ERR=$?
	  if [ $ERR -ne 0 ]; then
  		echo "There was a problem installing $package."
	  	echo "Installation will terminate here."
  		exit 1;
  	fi
  done
fi

# Check the build environment

for build in gcc ld make; do
	if ! systemHas $build; then
		echo
		echo "** Your system doesn't appear to include a working software build environment, which"
		echo "   is required for neet installation. What kind of pentester doesn't have a build"
		echo "   environment? Debian/Ubuntu users are advised to install the gcc, make, autoconf,"
		echo "   automake, flex and bison packages. Fedora and Mandrake users are advised to"
		echo "   upgrade to a decent distribution. Gentoo users should never, ever read this."
		echo
		touch install/error
		exit 1
	fi
done

# Check the base dependencies
echo
echo "Checking that your system has the required dependencies..."
echo
cd install/
./checkdeps.pl
ERROR=$?
cd "$INST"
[ -f install/dependencyErrors.log ] && mv install/dependencyErrors.log .
echo
if [ $ERROR -eq 2 ]; then
	echo "Unmet critical dependencies. Will not continue installing."
	echo "See the following log file: dependencyErrors.log"
	touch install/error
	exit 2
fi

# Clean up existing installation first
. ./uninstall.sh

echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo
echo "Installing the Neet Discovery Engine to ${NEET}..."

install/coreinstall.sh

cd $INST

####################################

# Now invoke neet-update to install the rest of the packages
${NEET}/bin/neet-update

# Ensure that the location information is up to date
${NEET}/bin/updateLocations

# Finally, set up the file permissions
chown -R root.root "$NEET"
chmod -R go-w "$NEET"
chmod -R +X "$NEET"
chmod 755 ${NEET}/bin/*

####################################
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo

echo "Neet $VERSION has been installed."

MISSING=""
WARN=0
for component in resources deps shell upload bundled; do
	if ! grep "neet-${component}=" ${CONFDIR}/versions >/dev/null 2>&1; then
		WARN=1
		MISSING="$MISSING $component"
	fi
done

if [ $WARN -eq 1 ]; then
	cat << EOM

  == WARNING ==
  One or more critical components were not installed. This could happen if you
  currently have no Internet access, or if the proxy is not set up correctly to
  retrieve content from GitHub. To correct this, please check your connectivity
  and then run neet-update.

  The following components were missing:

EOM
	for component in $MISSING; do
		echo "   - neet-$component"
	done
fi

cat << EOF

Thank you for installing Neet. Please review the man pages and the HTML
documentation supplied in the doc directory to find out how to get the best
from it.

EOF

