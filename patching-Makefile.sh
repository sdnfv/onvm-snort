#!/bin/bash

_PATCH_FILE_NAME=Makefile.patched
_MAIN_FILE_TO_PATCH=Makefile.dpdk


if [ ! -e $_MAIN_FILE_TO_PATCH ];then
	echo "File '$_MAIN_FILE_TO_PATCH' not exits in current directory"
	exit 10
fi
# Insert Directory of Cloned Repo
read -p "onvm-snort cloned at [$(realpath `pwd`/..)] (example: /home/user): " _DIR || exit 10
if [ -z "_DIR" ]
then
	_DIR=$HOME
fi
_DIR=${_DIR:-$(realpath `pwd`/..)}/onvm-snort/

read -p "Snort will install to [/usr/local/] (example: /opt/snort): " _SNORT_INSTALL || exit 10
if [ -z "$_SNORT_INSTALL" ]
then
	_SNORT_INSTALL=/opt/snort
fi
_SNORT_INSTALL=${_SNORT_INSTALL:-/usr/local/}

read -p "DAQ Install PATH [Using System as Default] (example: /opt/daq): " _DAQ_INSTALL || exit 10
if [ -z "$_DAQ_INSTALL" ]
then
	_DAQ_INSTALL=/opt/daq
fi
_DAQ_INSTALL=${_DAQ_INSTALL:- }

# Create patched file
cat $_MAIN_FILE_TO_PATCH | sed "s|/users/graceliu/snort/|$_DIR|g" | tee $_PATCH_FILE_NAME 1>/dev/null 2>&1 || exit 10

# Replace new DIR
sed -i "s|/users/graceliu/|$_DIR|g" $_PATCH_FILE_NAME || exit 10

# Replace Prefix of Snort
sed -i "s|prefix = /usr/local|prefix = $_SNORT_INSTALL|g" $_PATCH_FILE_NAME || exit 10

if [ "$_DAQ_INSTALL" != " " ]; then
	# Replace Libraries Path of DAQ
	sed -i "s|-L/usr/local/lib|-L${_DAQ_INSTALL}/lib|g" $_PATCH_FILE_NAME || exit 10

	# Replace CPPFLAGS
	sed -i "s|CPPFLAGS = |CPPFLAGS = -I${_DAQ_INSTALL}/include |g" $_PATCH_FILE_NAME || exit 10

	# Replace LDFLAGS
	sed -i "s|LDFLAGS =  -lpcre -L/usr/lib -ldumbnet|LDFLAGS = -L${_DAQ_INSTALL}/lib -lpcre -ldumbnet|g" $_PATCH_FILE_NAME || exit 10
fi

echo "Patched file saved to '$_PATCH_FILE_NAME'"

