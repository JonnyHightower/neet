# This file is sourced by the main install script

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

# Jonathan Roach, 2009
function Install {
	local pkg=$1
	local name=$2
	local config="$3"
	local configured
	local makefile
	cd "${BUILD}"
	#echo "**************************************"
	tar -xf "${SRC}/${pkg}.tar"
	if [ ! -d ${pkg} ]; then
		echo "Couldn't extract ${name}. Quitting"
		return 1
	fi
	cd ${pkg}

	if [ -x pre-install.sh ]; then
		echo -n "Installing ${name} ...: "
		./pre-install.sh "${PREFIX}" "${pkg}"
		if [ $? -eq 0 ]; then
			echo "${name} installed successfully"
			cd "${BUILD}" && rm -r "${pkg}"
		else
			echo "FAILED to install ${name}"
		fi
	else
		# No install script. Build it ourselves
		configured=0
		if [ -x configure ]; then
			echo "Configuring ${name}"
			./configure --prefix=${NEET}/external/ ${config} > "${BUILD}/${name}-install.log" 2>&1
			if [ $? -ne 0 ]; then
				echo "FAILED to configure ${name}"
				return 1
			fi
			configured=1
		elif [ -x ./config ]; then
			echo "Configuring ${name}"
			./config --prefix=${NEET}/external/ ${config} > "${BUILD}/${name}-install.log" 2>&1
			if [ $? -ne 0 ]; then
				echo "FAILED to configure ${name}"
				return 1
			fi
			configured=1
		fi
		echo -n "Compiling ${name} ...: "

		if [ -f Makefile ]; then
			makefile=1
			make >> "${BUILD}/${name}-install.log" 2>&1
			if [ $? -ne 0 ]; then
				echo "FAILED to build ${name}"
				return 1
			fi

			if [ $configured -eq 1 ]; then
				echo -n "Installing ${name} ...: "
				make install >> "${BUILD}/${name}-install.log" 2>&1
				if [ $? -ne 0 ]; then
					if [ -x post-install.sh ]; then
						./post-install.sh ${PREFIX}
						if [ $? -eq 0 ]; then
							echo "${name} installed successfully"
							cd "${BUILD}" && rm -r "${pkg}"
						else
							echo "FAILED to install ${name}"
						fi
					else
						echo "FAILED to install ${name}"
					fi
				else
					echo "${name} installed successfully"
					cd "${BUILD}" && rm -r "${pkg}"
				fi
			else
				# Makefile, but no configure script.
				local output=`grep ^all: Makefile | awk {print'$2'}`  >> "${BUILD}/${name}-install.log" 2>&1
				cp $output ${NEET}/external/bin/  >> "${BUILD}/${name}-install.log" 2>&1
				if [ $? -ne 0 ]; then
					if [ -x post-install.sh ]; then
						./post-install.sh ${PREFIX}
						if [ $? -eq 0 ]; then
							echo "${name} installed successfully"
							cd "${BUILD}" && rm -r "${pkg}"
						else
							echo "FAILED to install ${name}"
						fi
					else
						echo "FAILED to install ${name}"
					fi
				else
					echo "${name} installed successfully"
					cd "${BUILD}" && rm -r "${pkg}"
				fi
			fi
	
		else

			# No Makefile. Hopefully a very simple tool
			if [ `ls *.c | wc -l` -eq 1 ]; then
				local sourcename=*.c
				local outname=`echo $sourcename | sed -e s/.c$//`
				gcc -lssl -o $outname $sourcename  >> "${BUILD}/${name}-install.log" 2>&1
				if [ $? -eq 0 ]; then
					echo "Installing ${name}"
					cp $outname ${NEET}/external/bin/ >> "${BUILD}/${name}-install.log" 2>&1
					cd "${BUILD}" && rm -r "${pkg}"
				else
					echo "Couldn't build ${name}."
					#return 1
				fi
			else
				echo "Don't know how to build ${name}."
				#return 1
			fi
		fi
	fi

	cd ${INST}
}

function PkgInstall {
	local pkg=$1
	local name=$2
	cd "${BUILD}"
	tar -xf "${SRC}/${pkg}.tar" > "${BUILD}/${name}-install.log" 2>&1
	if [ ! -d ${pkg} ]; then
		echo "Couldn't extract ${name}. Quitting"
		return 1
	fi
	cp -Rp ${pkg} ${NEET}/external/ >> "${BUILD}/${name}-install.log" 2>&1
	if [ $? -eq 0 ]; then
		if [ -x "${NEET}/external/${pkg}/post-install.sh" ]; then
			cd "${NEET}/external/${pkg}" && ./post-install.sh "${PREFIX}"
		fi
		echo "Package ${name} was installed successfully"
		cd "${BUILD}"
		rm -r ${pkg}
	else
		echo "Couldn't install ${name}"
	fi
	cd ${INST}
}

function systemHas {
	local name=$1
	if type "$name" >/dev/null 2>&1; then
		true
	else
		false
	fi
}

function pathTo {
	local name=$1
	which $name
}

function newLocation {
	local name=$1
	local path=$2
	owd=$PWD
	if [ -e $path ]; then
		cd "${CONFDIR}"
		if [ ! -f locations ]; then
			touch locations
		fi
		cat locations | grep -v "^${name}=" > locations.tmp
		echo "${name}=$path" >> locations.tmp
		mv locations.tmp locations
		cd "$owd"
	fi
}

function rmLocation {
	local name=$1
	owd=$PWD
	cd "${CONFDIR}"
	cat locations | grep -v "^${name}=" > locations.tmp
	mv locations.tmp locations
	cd "$owd"
}

function newVersion {
	local name=$1
	local version=$2
	owd=$PWD
	cd "${CONFDIR}"
	if [ ! -f versions ]; then
		touch versions
	fi
	cat versions | grep -v "^${name}=" > versions.tmp
	echo "${name}=$version" >> versions.tmp
	mv versions.tmp versions
	cd "$owd"
}

function rmVersion {
	local name=$1
	owd=$PWD
	cd "${CONFDIR}"
	cat versions | grep -v "^${name}=" > versions.tmp
	mv versions.tmp versions
	cd "$owd"
}

# Make sure package is at least a particular version

function minVersion {
	local pkg=$1
	local ver=$2
	error=1
	if [ -f "${CONFDIR}/versions" ]; then
		version=`grep "^${pkg}=" "${CONFDIR}/versions" 2>/dev/null | awk -F= {print'$2'}`
		if [ -z $ver ] && grep "^${pkg}=" "${CONFDIR}/versions" >/dev/null 2>&1; then
			error=0
		elif [ ! -z $version ]; then
			# Installed version
			local a=`echo $version | awk -F. {print'$1'}`
			local b=`echo $version | awk -F. {print'$2'}`
			local c=`echo $version | awk -F. {print'$3'}`
			# Min version
			local d=`echo $ver | awk -F. {print'$1'}`
			local e=`echo $ver | awk -F. {print'$2'}`
			local f=`echo $ver | awk -F. {print'$3'}`
			#echo "Min $d $e $f  Act $a $b $c [$error]"
			if [ $a -gt $d ]; then
				error=0
			elif [ $a -eq $d ]; then
				if [ $b -gt $e ]; then
					error=0
				elif [ $b -eq $e ]; then
					if [ $c -gt $f ]; then
						error=0
					elif [ $c -eq $f ]; then
						error=0
					fi
				fi
			fi
		fi
	fi
	return $error
}

