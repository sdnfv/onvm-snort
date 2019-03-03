#! /bin/bash

#                        openNetVM
#                https://sdnfv.github.io
#
# OpenNetVM is distributed under the following BSD LICENSE:
#
# Copyright(c)
#       2015-2016 George Washington University
#       2015-2016 University of California Riverside
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
# * The name of the author may not be used to endorse or promote
#   products derived from this software without specific prior
#   written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

_PATCH_FILE_NAME=Makefile.patched
_MAIN_FILE_TO_PATCH=Makefile.dpdk


if [ ! -e $_MAIN_FILE_TO_PATCH ];then
	echo "File '$_MAIN_FILE_TO_PATCH' not exits in current directory"
	exit 10
fi
# Insert Directory of Cloned Repo
read -p "onvm-snort cloned at [$(realpath `pwd`/..)] (example: /home/user): " _DIR || exit 10
#if [ -z "_DIR" ]
#then
#	_DIR=$HOME
#fi
_DIR=${_DIR:-$(realpath `pwd`/..)}/onvm-snort/

read -p "Snort will install to [/usr/local/] (example: /opt/snort): " _SNORT_INSTALL || exit 10
#if [ -z "$_SNORT_INSTALL" ]
#then
#	_SNORT_INSTALL=/opt/snort
#fi
_SNORT_INSTALL=${_SNORT_INSTALL:-/usr/local/}

read -p "DAQ Install PATH [Using System as Default] (example: /opt/daq): " _DAQ_INSTALL || exit 10
#if [ -z "$_DAQ_INSTALL" ]
#then
#	_DAQ_INSTALL=/opt/daq
#fi
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

