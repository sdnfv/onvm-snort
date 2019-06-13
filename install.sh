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

./setenv.sh
source ~/.bashrc

# Base directory
BASE_DIR=$(pwd)

# update
sudo apt-get update

cd $RTE_SDK
make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
make -j7 T=$RTE_TARGET O=$RTE_TARGET
sudo make install T=x86_64-native-linuxapp-gcc

# Compile DAQ
sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev libssl-dev autoconf

cd $BASE_DIR/daq*

make clean
aclocal
autoconf
autoheader
automake -a

./configure --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm

make -j7
sudo make install

# Compile snort
cd $BASE_DIR/snort*
./configure --enable-sourcefire

cd snort*/src
make clean
cp ../../Makefile.patched Makefile
make -j7
sudo make install

sudo ldconfig

sudo cp -r snort*/simple-etc /etc/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

cd $ONVM_HOME
scripts/install.sh
cd onvm && make

cd $BASE_DIR
