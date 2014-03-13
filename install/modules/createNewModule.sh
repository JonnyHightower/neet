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

# Creates a new neet module from the template.

SOURCE=Template/Template.gsm.temp

if [ ! -f "$SOURCE" ]; then
	echo "You need to be in the neet modules directory for this to work!"
	exit 1;
fi

file="_temp$$"
touch "$file"
if [ ! -f "$file" ]; then
	echo "You don't appear to have write permissions in this directory."
	exit 1
fi
rm "$file"

echo "==> Please enter the new name for your module, omitting any file exension."
echo "    This is CASE SENSITIVE."
read module
module=`echo $module | sed  -e 's/\W//g'`
modfile=${module}.gsm

if [ ! -f "${module}/$modfile" ]; then
	echo "	* Creating new module $module from $SOURCE *"
	mkdir "$module"
	service=`echo $module | perl -e 'print lc(<STDIN>)'`
	cat "$SOURCE" | sed -e "s/__TEMPLATE__/$module/g" -e "s/{'Enabled'}=0/{'Enabled'}=1/g" -e "s/__SERVICE__/$service/g" > "${module}/$modfile"
else
	echo "  * A module with this name already exists! *"
	exit 1
fi


