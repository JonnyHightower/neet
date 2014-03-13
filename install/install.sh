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

if [ `id -u` -ne 0 ]; then
	echo "You must be root to install Neet."
	exit 1
fi

if [ ! -d install ] || [ ! -d public ] || [ ! -d main ] || [ ! -d modules ]; then
  echo "You must run this script from the topmost install directory."
   exit 1
fi

VERSION=`cat install/VERSION`
PREFIX=/opt
BINDIR="/usr/local/bin"

export PREFIX
echo
echo "Neet Discovery Engine v${VERSION} - Installing..."
echo " - Jonathan Roach"
echo
cat << EOF
    Copyright (C) 2008-2014 Jonathan Roach
    This program comes with ABSOLUTELY NO WARRANTY
    This is free software, and you are welcome to redistribute it
    under certain conditions; view the accompanying LICENSE for details.
EOF

export NEETINSTALLER=1
export NEET="${PREFIX}/neet"
export CONFDIR="${NEET}/etc"
export CONFIG="${CONFDIR}/neet.conf"
export EXTBIN=${NEET}/external/bin
export HELPBIN=${NEET}/helpers/bin
export INST=${PWD}
export SRC="${INST}/public"
export BUILD="${INST}/build"

#echo "INSTALLING IN $INST BUILD $BUILD"
#exit 1

# Import some functions
. ./install/functions.sh

[ -f install/error ] && rm install/error
[ ! -d build ] && mkdir build

# If this is Kali, do the prep
if [ -f /etc/debian_version ] && grep "Kali Linux 1" /etc/debian_version >/dev/null; then
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

elif [ -d /pentest/tunneling/pwnat ]; then
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

# Base permissions
umask 022

if ! mkdir -p "${EXTBIN}"; then
	echo "Couldn't create the Neet home directory ${NEET}. Quitting."
	touch install/error
	exit 1
fi

# Config information
mkdir -p "$CONFDIR"
echo "neetbase=${NEET}" > "${CONFDIR}/locations"
cat install/locations >> "${CONFDIR}/locations"

for dir in helpers/bin modules core; do
  mkdir -p "${NEET}/$dir" 2>/dev/null
done

cd main
cp helpers/* "${NEET}/helpers/bin/"
for subdir in bin etc resources; do
	cp -R "${subdir}" "${NEET}/"
done

# Perl modules
cp -R JR Neet "${NEET}/core/"

cd $INST
# Now, set up links to the directories in the main PATH
for bin in neet neet-maint neetsh; do
	ln -sf ${NEET}/bin/${bin} ${BINDIR}/${bin} 2>/dev/null
done

# Somewhere for the documentation to go
mkdir ${NEET}/doc

# Public packages
PPKG=Net-PcapUtils-0.01
cd public
tar xzf ${PPKG}.tar.gz && cd ${PPKG}/ && perl Makefile.PL && make && make install
cd $INST

echo

# Now the man pages
MANIN=0
if [ -f /etc/manpath.config ]; then
	for path in `grep ^MANDATORY_MANPATH /etc/manpath.config | grep /usr/local/ | awk {print'$2'}`; do
		if [ -d "$path/man1/" ]; then
			cp main/man/*.gz ${path}/man1/
			MANIN=1
			MANPATH=$path
			break
		fi
	done
else
	for path in `echo $MANPATH | sed -e 's/:/ /g'`; do
		if [ -d "$path/man1" ]; then
			cp main/man/*.gz ${path}/man1/
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
	cp main/man/*.gz ${path}/man1/
	[ $? -eq 0 ] && MANIN=1 && MANPATH=$path
fi

if [ $MANIN -eq 1 ]; then
	echo "Man pages have been installed into $MANPATH/man1"
fi

##########################
# Install bundled packages

# Firstly copy the stand-alone executables
cp bundled/* "${EXTBIN}/"

# SBG (bannergraber)
	Install sbg SBG
	if [ $? -eq 0 ]; then
		echo "sbg=${EXTBIN}/sbg" >> "${CONFDIR}/locations"
	fi

# TNS Enumerator
	Install tnsenum TNSEnum
	if [ $? -eq 0 ]; then
		echo "tnsenum=${EXTBIN}/tnsenum" >> "${CONFDIR}/locations"
	fi

# OpenVAS NASL. Install it if we can't find it.
if ! type openvas-nasl >/dev/null 2>&1; then
	if ! type nasl >/dev/null 2>&1; then
		Install openvas-libraries "OpenVAS Libraries"
		if [ $? -eq 0 ]; then
			OV=`type openvas-nasl 2>/dev/null | awk {print'$3'}`
			echo "openvas-nasl=$OV" >> "${CONFDIR}/locations"
		fi
	else
		OV=`type nasl | awk {print'$3'}`
		echo "openvas-nasl=$OV" >> "${CONFDIR}/locations"
	fi
else
	OV=`type openvas-nasl | awk {print'$3'}`
	echo "openvas-nasl=$OV" >> "${CONFDIR}/locations"
fi

# THC Amap
if ! type amap >/dev/null 2>&1; then
	Install amap "THC Amap"
	if [ $? -eq 0 ]; then
		echo "amap=${NEET}/external/bin/amap " >> "${CONFDIR}/locations"
	fi
else
	OV=`type amap | awk {print'$3'}`
	echo "amap=$OV" >> "${CONFDIR}/locations"
fi

# Moriarty
 PkgInstall moriarty "Moriarty_Oracle_Enumeration"

# Nikto
 PkgInstall nikto Nikto

# On
 Install on On
 if [ $? -eq 0 ]; then
	echo "on=${EXTBIN}/on" >> "${CONFDIR}/locations"
 fi

# Patator
echo "patator=${EXTBIN}/patator_v0.3.py" >> "${CONFDIR}/locations"

# Metasploit Framework
# PkgInstall framework3 "Metasploit_Framework 3"
 # Update the framework
 #[ -x ${NEET}/external/framework3/msfcli ] && cd ${NEET}/external/framework3 && svn update
 cd $INST

# Metasploit Framework
 PkgInstall framework2 "Metasploit_Framework 2"
 # Update the framework
 #[ -x ${NEET}/external/framework2/msfcli ] && cd ${NEET}/external/framework2 && svn update
 cd $INST

# Ensure that the location information is up to date
${NEET}/bin/updateLocations

####################################
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo

# Update version information in the main executable
sed -e "s/__VERSION__/$VERSION/" -i "${NEET}/bin/neet"
sed -e "s/__VERSION__/$VERSION/" -i "${NEET}/bin/neet_exploit"
sed -e "s/__VERSION__/$VERSION/" -i "${NEET}/bin/neetshellfunc"

newVersion neet $VERSION
echo "The Neet Discovery Engine $VERSION has been installed."
echo

# Install the modules
cd modules
./install.sh
cd $INST

# Finally, set up the file permissions
chown -R root.root "$NEET"
chmod -R go-w "$NEET"
chmod -R +X "$NEET"
chmod 755 ${NEET}/bin/*
chmod 755 ${EXTBIN}/*
chmod 755 ${HELPBIN}/*

cat << EOF

Thank you for installing Neet. Please review the man pages and the HTML
documentation supplied in the doc directory to find out how to get the best
from it.

EOF

