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

ls | grep setenv.sh
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo please run this script in situ
	exit
fi

sudo apt-get install realpath

# Base directory
BASE_DIR=$(pwd)

grep RTE_TARGET ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export RTE_TARGET=x86_64-native-linuxapp-gcc >> ~/.bashrc
fi

grep DPDK_TARGET ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export DPDK_TARGET=x86_64-native-linuxapp-gcc >> ~/.bashrc
fi

cd $BASE_DIR/dpdk*
grep RTE_SDK ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export RTE_SDK=$(pwd) >> ~/.bashrc
fi

cd $BASE_DIR/openNetVM*
grep ONVM_HOME ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export ONVM_HOME=$(pwd) >> ~/.bashrc
fi

cd $BASE_DIR
ls | grep Makefile.patched
ANS=`echo $?`
if [ $ANS == 0 ]
then
	read -p "Do you want to create the snort Makefile again? (y/N): " ANS
else
	ANS='y'
fi

if [ "$ANS" == "y" ]
then
	./patching-Makefile.sh
	cp ./Makefile.patched $BASE_DIR/snort*/src/
fi

grep "/opt/snort" ~/.bashrc
ANS=`echo $?`
if [ $ANS == 0 ]
then
	echo export PATH=$PATH:/opt/snort/bin >> ~/.bashrc
fi

grep ONVM_NUM_HUGEPAGES ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export ONVM_NUM_HUGEPAGES=1024 >> ~/.bashrc
fi

# don't add to fstan if already added
grep "/mnt/fstab" /etc/fstab
ANS=`echo $?`
if [ $ANS == 0 ]
then
	export ONVM_SKIP_FSTAB=1
fi

echo using nics 06:00.0 and 06:00.1
grep ONVM_NIC_PCI ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo 'export ONVM_NIC_PCI=" 06:00.0 06:00.1 "' >> ~/.bashrc
fi

source ~/.bashrc

sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"

cd $BASE_DIR
