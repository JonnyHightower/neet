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

# This is the uninstaller for the Neet Global Service Monitor modules (GSMs)
export CONFDIR="/opt/neet/etc"
if [ ! -f "${CONFDIR}/locations" ]; then
	echo "Couldn't find Neet installation!"
	exit 1
fi
export NEET=`grep ^neetbase= ${CONFDIR}/locations | awk -F= {print'$2'}`

# Get rid of the modules and their resources
/bin/rm -f ${NEET}/modules/*.gsm
/bin/rm -f ${NEET}/modules/*.gsm.*
/bin/rm -rf ${NEET}/resources/modules/*

. util/functions.sh
rmVersion modulepack

echo "Neet module pack has been removed."

