#!/bin/bash

aclocal
autoconf
autoheader
automake -a
./configure --enable-static --disable-shared --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm
make clean
make -j4
sudo make install
sudo ldconfig
